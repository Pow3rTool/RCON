package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsCNGSigningAndEnrollmentResume(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("CNG machine-key test requires an elevated Administrator prompt")
	}
	etc := t.TempDir()
	if err := ensureIdentityDir(etc); err != nil {
		t.Fatal(err)
	}
	key, err := createDeviceKey(etc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		name, _ := cngKeyName(etc)
		h, err := cngOpen(name, false)
		if err != nil {
			t.Error(err)
			return
		}
		if code, _, _ := ncDelete.Call(h, ncSilent); code != 0 {
			ncFree.Call(h)
			t.Error(ncError("delete test key", code))
		}
	})
	digest := sha256.Sum256([]byte("rcon windows native signer test"))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatalf("signature: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := createDeviceKey(etc)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Public().(*ecdsa.PublicKey).Equal(reloaded.Public()) {
		t.Fatal("device key changed on restart")
	}
	if _, err := os.Stat(filepath.Join(etc, "device-key.pem")); !os.IsNotExist(err) {
		t.Fatal("private PEM unexpectedly exists")
	}
	if err := savePendingEnrollment(etc, "https://lab.example", "pending-test", key); err != nil {
		t.Fatal(err)
	}
	if id, err := pendingEnrollmentID(etc, "https://lab.example", reloaded); err != nil || id != "pending-test" {
		t.Fatalf("resume: %q %v", id, err)
	}
	if _, err := pendingEnrollmentID(etc, "https://wrong.example", key); err == nil {
		t.Fatal("accepted mismatched endpoint")
	}
	name, _ := cngKeyName(etc)
	h, err := cngOpen(name, false)
	if err != nil {
		t.Fatal(err)
	}
	defer ncFree.Call(h)
	var n uint32
	privateBlob := make([]byte, 104)
	code, _, _ := ncExport.Call(h, 0, uintptr(unsafe.Pointer(utf16("ECCPRIVATEBLOB"))), 0,
		uintptr(unsafe.Pointer(&privateBlob[0])), uintptr(len(privateBlob)), uintptr(unsafe.Pointer(&n)), 0)
	if code == 0 {
		t.Fatal("private key unexpectedly exportable")
	}
}
func TestWindowsMetadataRejectedBeforeWrite(t *testing.T) {
	w := httptest.NewRecorder()
	writeFile(w, httptest.NewRequest("POST", "/write", bytes.NewBufferString(`{"path":"does-not-exist.txt","content":"test","mode":"0600"}`)))
	if w.Code != 422 {
		t.Fatalf("metadata response: %d %s", w.Code, w.Body.String())
	}
}
func TestWindowsUpdateRejectsBeforeStaging(t *testing.T) {
	testReleaseKey(t)
	store := NewJobStore()
	// sha256 of the three zero bytes that "AAAA" decodes to.
	const zeros = "709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c"
	for _, test := range []struct {
		body string
		code int
	}{
		// No version, traversal, DOS device name, wrong platform.
		{`{}`, 400},
		{`{"version":"..\\evil"}`, 400},
		{`{"version":"CON"}`, 400},
		{`{"version":"v1","goos":"linux"}`, 400},
		// Hash mismatch, then a matching hash with a bad signature.
		{`{"version":"v9.9.9-test","sha256":"x","binary_b64":"AAAA"}`, 400},
		{`{"version":"v9.9.9-test","sha256":"` + zeros + `","binary_b64":"AAAA","signature":"AAAA"}`, 403},
	} {
		w := httptest.NewRecorder()
		updateApply("", "", store)(w, httptest.NewRequest("POST", "/update/apply", bytes.NewBufferString(test.body)))
		if w.Code != test.code {
			t.Fatalf("%s: got %d %s, want %d", test.body, w.Code, w.Body.String(), test.code)
		}
	}
	if _, err := os.Stat(windowsPath("releases", "v9.9.9-test")); !os.IsNotExist(err) {
		t.Fatalf("a rejected release was staged: %v", err)
	}
	if drainReason() != "" || upgrading.Load() {
		t.Fatal("a rejected release left the node draining")
	}
}

func TestWindowsServiceCommandLineRewrite(t *testing.T) {
	prev := `C:\RCON\releases\v1\rcon.exe service --etc "C:\RCON\etc"`
	argv, err := windows.DecomposeCommandLine(prev)
	if err != nil {
		t.Fatal(err)
	}
	next := serviceCommandLine(`C:\RCON\releases\v2\rcon.exe`, argv[1:])
	got, err := windows.DecomposeCommandLine(next)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`C:\RCON\releases\v2\rcon.exe`, "service", "--etc", `C:\RCON\etc`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("rewrite: %q -> %q", next, got)
	}
	if !strings.HasPrefix(next, `"C:\RCON\releases\v2\rcon.exe" `) {
		t.Fatalf("executable must always be quoted: %q", next)
	}
	etc, err := windowsServiceIdentityDir(next)
	if err != nil || etc != `C:\RCON\etc` {
		t.Fatalf("rewritten command no longer parses for uninstall: %q %v", etc, err)
	}
}

func TestWindowsFixedLayout(t *testing.T) {
	if defaultWindowsRoot != `C:\RCON` {
		t.Fatalf("installed root moved: %q", defaultWindowsRoot)
	}
	if windowsRoot == defaultWindowsRoot {
		t.Fatal("tests are pointed at the real installation root")
	}
	for got, want := range map[string]string{
		defaultIdentityDir(): filepath.Join(windowsRoot, "etc"),
		defaultAuditPath():   filepath.Join(windowsRoot, "logs", "audit.log"),
		releaseExe("v1.2.3"): filepath.Join(windowsRoot, "releases", "v1.2.3", "rcon.exe"),
		journalPath():        filepath.Join(windowsRoot, "state", "upgrade-pending.json"),
	} {
		if got != want {
			t.Fatalf("layout: %q, want %q", got, want)
		}
	}
}

func TestWindowsPinnedKeyName(t *testing.T) {
	dir := t.TempDir()
	derived, err := cngKeyName(dir)
	if err != nil || !pinnedKeyNameRE.MatchString(derived) {
		t.Fatalf("derived name %q %v", derived, err)
	}
	pinned := "Pow3rTool-RCON-0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(`{"key_name":"`+pinned+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := cngKeyName(dir); err != nil || got != pinned {
		t.Fatalf("pinned name ignored: %q %v", got, err)
	}
	for _, bad := range []string{"Other-Key", "Pow3rTool-RCON-../x", "Pow3rTool-RCON-0123"} {
		if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(`{"key_name":"`+bad+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cngKeyName(dir); err == nil {
			t.Fatalf("accepted key name %q", bad)
		}
	}
}

func TestWindowsJournalCommandValidation(t *testing.T) {
	h := &windowsUpgradeHost{}
	good := serviceCommandLine(releaseExe("v1"), []string{"service", "--etc", defaultIdentityDir()})
	if !h.ValidCommand(good, "v1") {
		t.Fatalf("rejected the release's own command %q", good)
	}
	for _, test := range []struct{ command, version string }{
		{good, "v2"}, // names a different release
		{serviceCommandLine(`C:\Temp\other.exe`, []string{"service"}), "v1"},
		{serviceCommandLine(releaseExe("v1"), []string{"swap"}), "v1"},
		{serviceCommandLine(releaseExe("v1"), nil), "v1"},
		{good, `..\v1`},
	} {
		if h.ValidCommand(test.command, test.version) {
			t.Fatalf("accepted %q for %q", test.command, test.version)
		}
	}
}

func TestWindowsUpgradeLockIsExclusive(t *testing.T) {
	unlock, ok, err := tryUpgradeLock()
	if err != nil || !ok {
		t.Fatalf("first lock: %v %v", ok, err)
	}
	if _, ok, err := tryUpgradeLock(); err != nil || ok {
		t.Fatalf("second lock while held: %v %v", ok, err)
	}
	unlock()
	unlock, ok, err = tryUpgradeLock()
	if err != nil || !ok {
		t.Fatalf("lock after release: %v %v", ok, err)
	}
	unlock()
}

func TestWindowsApplyRefusedWhileUpgradeUnsettled(t *testing.T) {
	testReleaseKey(t)
	if err := writeJournal(upgradeJournal{From: "v1", To: "v2"}); err != nil {
		t.Fatal(err)
	}
	defer removeJournal()
	w := httptest.NewRecorder()
	updateApply("", "", NewJobStore())(w, httptest.NewRequest("POST", "/update/apply", bytes.NewBufferString(`{"version":"v3"}`)))
	if w.Code != 409 {
		t.Fatalf("apply with a pending journal: %d %s", w.Code, w.Body.String())
	}
}

func TestWindowsRejectsUnsafePersistedCNGKeys(t *testing.T) {
	requireElevatedWindows(t)
	enableTestPrivilege(t, "SeRestorePrivilege")
	for _, test := range []struct {
		name   string
		export uint32
		acl    string
	}{
		{"exportable", 1, "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"},
		{"public-acl", 0, "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)"},
		{"untrusted-owner", 0, "O:BUD:P(A;;GA;;;SY)(A;;GA;;;BA)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, err := cngKeyName(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			provider, err := cngProvider()
			if err != nil {
				t.Fatal(err)
			}
			defer ncFree.Call(provider)
			var key uintptr
			code, _, _ := ncCreateKey.Call(provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16("ECDSA_P256"))), uintptr(unsafe.Pointer(utf16(name))), 0, ncMachine)
			if code != 0 {
				t.Fatal(ncError("create test key", code))
			}
			defer func() {
				if code, _, _ := ncDelete.Call(key, ncSilent); code != 0 {
					ncFree.Call(key)
					t.Error(ncError("delete test key", code))
				}
			}()
			code, _, _ = ncSetProperty.Call(key, uintptr(unsafe.Pointer(utf16("Export Policy"))), uintptr(unsafe.Pointer(&test.export)), 4, 0)
			if code != 0 {
				t.Fatal(ncError("set test export policy", code))
			}
			if code, _, _ = ncFinalize.Call(key, ncSilent); code != 0 {
				t.Fatal(ncError("finalize test key", code))
			}
			sd, err := windows.SecurityDescriptorFromString(test.acl)
			if err != nil {
				t.Fatal(err)
			}
			code, _, _ = ncSetProperty.Call(key, uintptr(unsafe.Pointer(utf16("Security Descr"))), uintptr(unsafe.Pointer(sd)), uintptr(sd.Length()), uintptr(windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)|0x80000000)
			if code != 0 {
				t.Fatal(ncError("set test key ACL", code))
			}
			if opened, err := cngOpen(name, true); err == nil {
				ncFree.Call(opened)
				t.Fatal("adopted unsafe persisted key")
			}
		})
	}
}
