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
func TestWindowsUpdateIsExplicitlyUnsupported(t *testing.T) {
	w := httptest.NewRecorder()
	updateApply("", "")(w, httptest.NewRequest("POST", "/update/apply", bytes.NewBufferString("{}")))
	if w.Code != 501 {
		t.Fatalf("update response: %d", w.Code)
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
