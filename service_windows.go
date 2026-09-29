package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsServiceName = "Pow3rToolRCON"

type windowsServiceConfig struct {
	XConnect string `json:"xconnect"`
	Broker   string `json:"broker"`
	Name     string `json:"name"`
	Token    string `json:"join_token,omitempty"`
	CAPin    string `json:"ca_pin,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	// The CNG device key's name, pinned so the identity directory can move
	// (see cngKeyName). Recorded at install; set by adopt-identity.
	KeyName string `json:"key_name,omitempty"`
}

func loadWindowsServiceConfig(etc string) (windowsServiceConfig, error) {
	var cfg windowsServiceConfig
	if err := ensureIdentityDir(etc); err != nil {
		return cfg, err
	}
	b, err := os.ReadFile(filepath.Join(etc, "service.json"))
	if err == nil {
		err = json.Unmarshal(b, &cfg)
	}
	return cfg, err
}
func saveWindowsServiceConfig(etc string, cfg windowsServiceConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(etc, "service-config-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(etc, "service.json"))
}
func platformCommand(args []string) bool {
	if len(args) == 0 {
		// Double-clicked in Explorer: run the interactive installer instead of
		// trying to serve from a console window.
		if isService, _ := svc.IsWindowsService(); !isService && launchedFromExplorer() {
			runInstall([]string{"--interactive"})
			return true
		}
		return false
	}
	switch args[0] {
	case "swap":
		runSwap(args[1:])
		return true
	case "service":
		fs := flag.NewFlagSet("service", flag.ExitOnError)
		etc := fs.String("etc", defaultIdentityDir(), "protected service data directory")
		_ = fs.Parse(args[1:])
		if ok, err := svc.IsWindowsService(); err != nil || !ok {
			log.Fatal("'service' must be started by Windows Service Control Manager; use 'install' first")
		}
		// Everything else happens inside Execute, so each startup failure is
		// reported to SCM as the service stopping with an error code.
		if err := svc.Run(windowsServiceName, &rconWindowsService{etc: *etc}); err != nil {
			log.Fatalf("service: %v", err)
		}
		return true
	case "adopt-identity":
		fs := flag.NewFlagSet("adopt-identity", flag.ExitOnError)
		from := fs.String("from", "", "existing identity directory to adopt, e.g. the preview layout's ProgramData one")
		_ = fs.Parse(args[1:])
		to := defaultIdentityDir()
		if err := adoptIdentity(*from, to); err != nil {
			log.Fatalf("adopt-identity: %v", err)
		}
		fmt.Printf("Identity adopted into %s and verified. Point the service at it: service --etc %s\n", to, to)
		return true
	case "uninstall":
		if len(args) != 1 {
			log.Fatal("usage: rcon.exe uninstall (preserves identity, logs, and binary)")
		}
		if err := uninstallWindowsService(); err != nil {
			log.Fatal(err)
		}
		return true
	}
	return false
}

// adoptIdentity copies an enrolled identity (e.g. the preview layout's
// ProgramData directory) into `to` without re-enrolling. The CNG device key
// can't be copied or renamed — it is non-exportable — so its name is pinned in
// the new service.json instead. The copy must load the very same certificate
// and key before this returns; the service is left untouched.
func adoptIdentity(from, to string) (err error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("run from an elevated prompt")
	}
	if from == "" || samePath(from, to) {
		return fmt.Errorf("--from must name a different identity directory")
	}
	cfg, err := loadWindowsServiceConfig(from) // trust-checks the source directory too
	if err != nil {
		return fmt.Errorf("source configuration: %w", err)
	}
	src, err := loadDeviceCertificate(from)
	if err != nil {
		return fmt.Errorf("source identity does not load: %w", err)
	}
	if cfg.KeyName, err = cngKeyName(from); err != nil {
		return err
	}
	cfg.Token = "" // never carry a join token forward
	if entries, err := os.ReadDir(to); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s already has content; refusing to overwrite an identity", to)
	}
	if err := ensureIdentityDir(to); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(to) // never leave a half-adopted identity behind
		}
	}()
	for _, name := range []string{"device-cert.pem", "trust-bundle.pem", "enrollment.json"} {
		b, err := os.ReadFile(filepath.Join(from, name))
		if os.IsNotExist(err) && name == "enrollment.json" {
			continue
		}
		if err != nil {
			return err
		}
		if err := replaceFileAtomic(filepath.Join(to, name), b, 0o600); err != nil {
			return err
		}
	}
	if err := saveWindowsServiceConfig(to, cfg); err != nil {
		return err
	}
	got, err := loadDeviceCertificate(to)
	if err != nil {
		return fmt.Errorf("adopted identity does not load: %w", err)
	}
	if string(got.Certificate[0]) != string(src.Certificate[0]) {
		return fmt.Errorf("adopted identity is not the source identity")
	}
	if _, _, err := buildTLS(to); err != nil {
		return fmt.Errorf("adopted identity: %w", err)
	}
	return nil
}

// servicePreflight is the service's startup path up to connecting to the
// service manager: configuration, protected directories, and the log file.
// --selftest runs it too, so the running (known-good) release refuses to hand
// off to a candidate that can't get through its own startup on this node.
func servicePreflight(etc string) (windowsServiceConfig, *os.File, error) {
	cfg, err := loadWindowsServiceConfig(etc)
	if err != nil {
		return cfg, nil, fmt.Errorf("service config: %w", err)
	}
	for _, d := range []string{windowsPath("logs"), windowsPath("state")} {
		if err := ensureIdentityDir(d); err != nil {
			return cfg, nil, fmt.Errorf("service data directory: %w", err)
		}
	}
	f, err := os.OpenFile(windowsPath("logs", "service.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return cfg, nil, fmt.Errorf("service log: %w", err)
	}
	return cfg, f, nil
}

type rconWindowsService struct {
	etc string
	cfg windowsServiceConfig
}

func (s *rconWindowsService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	// SCM startup completes before enrollment/network activity. Approval can
	// take hours without blocking Windows boot or producing service timeout 1053.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	// Stopping with an error code is a failure to SCM, whose recovery action
	// restarts the service with its configured command.
	fail := func(code uint32, format string, a ...any) (bool, uint32) {
		log.Printf(format, a...)
		status <- svc.Status{State: svc.StopPending}
		return true, code
	}
	// Upgrade recovery first: before configuration, directory checks and the
	// log file, any of which can fail. A new release that fails anywhere in
	// startup is still counted, and a crash loop rolls back.
	if serviceStartupRecovery() {
		return fail(selfRestartExitCode, "service: restarting into the previous release")
	}
	cfg, f, err := servicePreflight(s.etc)
	if err != nil {
		return fail(1, "service: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	s.cfg = cfg
	armPendingUpgrade() // watchdog or settling for an upgrade in flight at startup
	go func() {
		_ = os.Setenv("RCON_JOIN_TOKEN", s.cfg.Token)
		argv := []string{"--etc", s.etc, "--broker", s.cfg.Broker,
			"--audit-log", defaultAuditPath(), "--enroll-if-needed",
			"--xconnect", s.cfg.XConnect, "--name", s.cfg.Name, "--ca-pin", s.cfg.CAPin}
		if s.cfg.Insecure {
			argv = append(argv, "--insecure")
		}
		runAgent(argv)
	}()
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				log.Printf("service: stopping; active command Job Objects will terminate with the process")
				dropCurConn()
				return false, 0
			}
		case reason := <-selfRestart:
			// Exiting with an error code is a failure to SCM, whose recovery
			// action restarts the service with its (just changed) command.
			status <- svc.Status{State: svc.StopPending}
			log.Printf("service: restarting through service recovery: %s", reason)
			dropCurConn()
			return true, selfRestartExitCode
		}
	}
}

var errRelaunched = errors.New("relaunched elevated")

func runInstall(args []string) {
	interactive := false
	for _, a := range args {
		interactive = interactive || a == "--interactive" || a == "-interactive"
	}
	err := installWindowsService(args)
	if err == errRelaunched {
		return // the elevated copy has its own window
	}
	if interactive {
		if err != nil {
			fmt.Printf("\nInstall FAILED: %v\n", err)
		}
		pauseBeforeExit()
		if err != nil {
			os.Exit(1)
		}
		return
	}
	if err != nil {
		log.Fatalf("install: %v", err)
	}
}
func installWindowsService(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	interactive := fs.Bool("interactive", false, "prompt for missing settings (what a double-click runs)")
	xc := fs.String("xconnect", "", "HTTPS XConnect bootstrap base URL (required)")
	token := fs.String("token", os.Getenv("RCON_JOIN_TOKEN"), "join token; omit it to be prompted with hidden input")
	broker := fs.String("broker", "", "broker host:port (default XConnect host:3)")
	name := fs.String("name", "", "requested node name (default hostname)")
	pin := fs.String("ca-pin", os.Getenv("RCON_CA_PIN"), "optional out-of-band enrollment CA pin")
	insecure := fs.Bool("insecure", false, "unsupported: install the bootstrap CA in the OS trust store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		if *interactive {
			// Carry the non-secret settings across elevation. The join token never
			// goes on a command line; the elevated copy prompts for it.
			relaunch := []string{"install", "--interactive"}
			for _, f := range []struct{ flag, value string }{
				{"--xconnect", *xc}, {"--broker", *broker}, {"--name", *name}, {"--ca-pin", *pin},
			} {
				if f.value != "" {
					relaunch = append(relaunch, f.flag, syscall.EscapeArg(f.value))
				}
			}
			if err := relaunchElevated(strings.Join(relaunch, " ")); err != nil {
				return fmt.Errorf("Administrator rights are required: %w", err)
			}
			return errRelaunched
		}
		return fmt.Errorf("run from an elevated (Administrator) prompt, or double-click rcon.exe")
	}
	if *interactive {
		fmt.Printf("Pow3rTool RCON installer (%s)\n\n", version)
		var err error
		if *xc == "" {
			if *xc, err = promptLine("XConnect bootstrap URL (https://...): "); err != nil {
				return err
			}
		}
		if *name == "" {
			host, _ := os.Hostname()
			if *name, err = promptLine(fmt.Sprintf("Node name [%s]: ", host)); err != nil {
				return err
			}
		}
		if *pin == "" {
			if *pin, err = promptLine("CA pin, sha256:... (optional, Enter to skip): "); err != nil {
				return err
			}
		}
	}
	if err := validateBootstrapURL(*xc, *insecure); err != nil {
		return err
	}
	u, _ := url.Parse(*xc)
	if *token == "" {
		if !stdinIsConsole() {
			return fmt.Errorf("no join token: run from a console to be prompted, or set RCON_JOIN_TOKEN")
		}
		t, err := promptSecret("Orthanc join token (input hidden): ")
		if err != nil {
			return err
		}
		if *token = strings.TrimSpace(t); *token == "" {
			return fmt.Errorf("a join token is required")
		}
	}
	if *broker == "" {
		*broker = net.JoinHostPort(u.Hostname(), "3")
	}
	if _, _, err := net.SplitHostPort(*broker); err != nil {
		return fmt.Errorf("invalid broker address: %w", err)
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService(windowsServiceName); err == nil {
		existing.Close()
		return fmt.Errorf("%s is already installed. It upgrades itself from the signed release channel; "+
			"to reinstall, run 'rcon.exe uninstall' first", windowsServiceName)
	} else if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return err
	}
	if !validReleaseVersion(version) {
		return fmt.Errorf("this build's version %q cannot name a release directory", version)
	}
	etc := defaultIdentityDir()
	for _, d := range []string{etc, windowsPath("logs"), windowsPath("state")} {
		if err := ensureIdentityDir(d); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(etc, "service.json")); err == nil {
		return fmt.Errorf("existing service.json retained from an earlier install; preserve it and follow the reinstall instructions")
	} else if !os.IsNotExist(err) {
		return err
	}
	target := releaseExe(version)
	if err := ensureIdentityDir(filepath.Dir(target)); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if !samePath(exe, target) {
		b, err := os.ReadFile(exe)
		if err != nil {
			return err
		}
		if err := replaceFileAtomic(target, b, 0o755); err != nil {
			return err
		}
	}
	cfg := windowsServiceConfig{XConnect: strings.TrimRight(*xc, "/"), Broker: *broker, Name: *name, Token: *token, CAPin: *pin, Insecure: *insecure}
	if cfg.KeyName, err = cngKeyName(etc); err != nil {
		return err
	}
	if err := saveWindowsServiceConfig(etc, cfg); err != nil {
		return err
	}
	service, err := manager.CreateService(windowsServiceName, target, mgr.Config{
		DisplayName: "Pow3rTool RCON", Description: "Local administrative agent; outbound authenticated Pow3rTool connection.",
		StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem", DelayedAutoStart: true,
	}, "service", "--etc", etc)
	if err != nil {
		return err
	}
	defer service.Close()
	// Restart after any failure, including an exit with an error code: the
	// upgrade path restarts the service through this recovery action.
	if err := ensureRestartOnFailure(service); err != nil {
		return err
	}
	if err := service.Start(); err != nil {
		return err
	}
	fmt.Printf("Installed %s %s as LocalSystem from %s. Approve %q in Orthanc.\nLog: %s\n",
		windowsServiceName, version, target, *name, windowsPath("logs", "service.log"))
	return nil
}

func uninstallWindowsService() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("run PowerShell as Administrator first")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	cfg, err := service.Config()
	if err != nil {
		return err
	}
	etc, err := windowsServiceIdentityDir(cfg.BinaryPathName)
	if err != nil {
		return fmt.Errorf("locate installed service configuration: %w", err)
	}
	st, err := service.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Stopped {
		if _, err := service.Control(svc.Stop); err != nil {
			return err
		}
		deadline := time.Now().Add(30 * time.Second)
		for st.State != svc.Stopped {
			if time.Now().After(deadline) {
				return fmt.Errorf("service did not stop; nothing deleted")
			}
			time.Sleep(250 * time.Millisecond)
			st, err = service.Query()
			if err != nil {
				return err
			}
		}
	}
	if err := clearWindowsJoinToken(etc); err != nil {
		return fmt.Errorf("service stopped but not removed: cannot clear retained join token: %w", err)
	}
	if err := service.Delete(); err != nil {
		return err
	}
	fmt.Printf("Service removed and join token cleared. Releases, identity, CNG key, and logs under %s retained. Revoke the node in Orthanc if retiring it.\n", windowsRoot)
	return nil
}

// Read the actual SCM command, including a custom --etc path, before uninstall.
func windowsServiceIdentityDir(command string) (string, error) {
	args, err := windows.DecomposeCommandLine(command)
	if err != nil || len(args) < 2 || args[1] != "service" {
		return "", fmt.Errorf("unrecognized service command")
	}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	etc := fs.String("etc", defaultIdentityDir(), "")
	if err := fs.Parse(args[2:]); err != nil {
		return "", err
	}
	if fs.NArg() != 0 || !filepath.IsAbs(*etc) {
		return "", fmt.Errorf("service requires an absolute --etc directory")
	}
	return *etc, nil
}
