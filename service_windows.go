package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
}

func windowsProgramDir() (string, error) {
	p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	return filepath.Join(p, "Pow3rTool", "RCON"), err
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
		return false
	}
	switch args[0] {
	case "service":
		fs := flag.NewFlagSet("service", flag.ExitOnError)
		etc := fs.String("etc", defaultIdentityDir(), "protected service data directory")
		_ = fs.Parse(args[1:])
		if ok, err := svc.IsWindowsService(); err != nil || !ok {
			log.Fatal("'service' must be started by Windows Service Control Manager; use 'install' first")
		}
		cfg, err := loadWindowsServiceConfig(*etc)
		if err != nil {
			log.Fatalf("service config: %v", err)
		}
		f, err := os.OpenFile(filepath.Join(*etc, "service.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("service log: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
		if err := svc.Run(windowsServiceName, &rconWindowsService{etc: *etc, cfg: cfg}); err != nil {
			log.Fatalf("service: %v", err)
		}
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

type rconWindowsService struct {
	etc string
	cfg windowsServiceConfig
}

func (s *rconWindowsService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	// SCM startup completes before enrollment/network activity. Approval can
	// take hours without blocking Windows boot or producing service timeout 1053.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	go func() {
		_ = os.Setenv("RCON_JOIN_TOKEN", s.cfg.Token)
		argv := []string{"--etc", s.etc, "--broker", s.cfg.Broker,
			"--audit-log", filepath.Join(s.etc, "audit.log"), "--enroll-if-needed",
			"--xconnect", s.cfg.XConnect, "--name", s.cfg.Name, "--ca-pin", s.cfg.CAPin}
		if s.cfg.Insecure {
			argv = append(argv, "--insecure")
		}
		runAgent(argv)
	}()
	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			log.Printf("service: stopping; active command Job Objects will terminate with the process")
			dropCurConn()
			return false, 0
		}
	}
	return false, 0
}

func runInstall(args []string) {
	if err := installWindowsService(args); err != nil {
		log.Fatalf("install: %v", err)
	}
}
func installWindowsService(args []string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("run PowerShell as Administrator first")
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	xc := fs.String("xconnect", "", "HTTPS XConnect bootstrap base URL (required)")
	token := fs.String("token", os.Getenv("RCON_JOIN_TOKEN"), "join token; prefer RCON_JOIN_TOKEN environment variable")
	broker := fs.String("broker", "", "broker host:port (default XConnect host:3)")
	name := fs.String("name", "", "requested node name (default hostname)")
	pin := fs.String("ca-pin", os.Getenv("RCON_CA_PIN"), "optional out-of-band enrollment CA pin")
	insecure := fs.Bool("insecure", false, "unsupported: install the bootstrap CA in the OS trust store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateBootstrapURL(*xc, *insecure); err != nil {
		return err
	}
	u, _ := url.Parse(*xc)
	if *token == "" {
		return fmt.Errorf("set RCON_JOIN_TOKEN or supply --token")
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
		return fmt.Errorf("%s already exists; use the documented stop/copy/start upgrade procedure", windowsServiceName)
	} else if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return err
	}
	etc := defaultIdentityDir()
	if err := ensureIdentityDir(etc); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(etc, "service.json")); err == nil {
		return fmt.Errorf("existing service.json retained from an earlier install; preserve it and follow the reinstall instructions")
	} else if !os.IsNotExist(err) {
		return err
	}
	dir, err := windowsProgramDir()
	if err != nil {
		return err
	}
	if err := ensureIdentityDir(dir); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	target := filepath.Join(dir, "rcon.exe")
	if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(target)) {
		b, err := os.ReadFile(exe)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o755); err != nil {
			return err
		}
	}
	cfg := windowsServiceConfig{XConnect: strings.TrimRight(*xc, "/"), Broker: *broker, Name: *name, Token: *token, CAPin: *pin, Insecure: *insecure}
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
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 86400); err != nil {
		return err
	}
	if err := service.Start(); err != nil {
		return err
	}
	fmt.Printf("Installed %s as LocalSystem. Approve %q in Orthanc.\nLog: %s\n", windowsServiceName, *name, filepath.Join(etc, "service.log"))
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
	fmt.Printf("Service removed and join token cleared. Binary, identity, CNG key, and logs retained. Revoke the node in Orthanc if retiring it.\n")
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
