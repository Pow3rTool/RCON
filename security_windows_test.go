package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsTrustedAncestorEnforcesSharing(t *testing.T) {
	requireElevatedWindows(t)
	path := filepath.Join(t.TempDir(), "ancestor")
	if err := ensureIdentityDir(path); err != nil {
		t.Fatal(err)
	}
	h, err := openTrustedPath(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	for _, access := range []uint32{windows.GENERIC_WRITE, windows.DELETE} {
		other, err := windows.CreateFile(utf16(path), access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err == nil {
			windows.CloseHandle(other)
			t.Fatalf("conflicting access %#x succeeded", access)
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Fatalf("unexpected conflicting-open error: %v", err)
		}
	}
	if err := os.Rename(path, path+"-moved"); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("rename was not excluded: %v", err)
	}
}

func requireElevatedWindows(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an elevated Administrator prompt")
	}
}

// Tests restore privileges/owners and delete only their temporary objects.
func enableTestPrivilege(t *testing.T, name string) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, utf16(name), &luid); err != nil {
		token.Close()
		t.Fatal(err)
	}
	requested := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	var previous windows.Tokenprivileges
	var n uint32
	if err := windows.AdjustTokenPrivileges(token, false, &requested, uint32(unsafe.Sizeof(previous)), &previous, &n); err != nil {
		token.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil); token.Close() })
}

func setTestSecurity(t *testing.T, path, sddl string, owner bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var sid *windows.SID
	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner {
		sid, _, err = sd.Owner()
		if err != nil {
			t.Fatal(err)
		}
		flags |= windows.OWNER_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCreatesProtectedDirectoryAndInheritedFile(t *testing.T) {
	requireElevatedWindows(t)
	path := filepath.Join(t.TempDir(), "new-parent", "identity")
	if err := ensureIdentityDir(path); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "service.json")
	if err := os.WriteFile(file, []byte(`{"join_token":"synthetic-test-only"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(path); err != nil {
		t.Fatalf("safe reuse: %v", err)
	}
	h, err := openTrustedPath(file, true, false)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
}

func TestWindowsRejectsUnsafeDirectoryOwner(t *testing.T) {
	requireElevatedWindows(t)
	enableTestPrivilege(t, "SeRestorePrivilege")
	path := t.TempDir()
	// A normal-users owner can restore permissions even with an admin-only DACL.
	setTestSecurity(t, path, "O:BUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true)
	t.Cleanup(func() { setTestSecurity(t, path, protectedDirectorySDDL, true) })
	if err := ensureIdentityDir(path); err == nil {
		t.Fatal("accepted untrusted owner")
	}
	if err := ensureIdentityDir(filepath.Join(path, "identity")); err == nil {
		t.Fatal("accepted untrusted ancestor owner")
	}
}

func TestWindowsRejectsPublicDirectoryAndChildACL(t *testing.T) {
	requireElevatedWindows(t)
	for _, child := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory", true: "child"}[child], func(t *testing.T) {
			path := t.TempDir()
			if err := ensureIdentityDir(path); err != nil {
				t.Fatal(err)
			}
			target := path
			if child {
				target = filepath.Join(path, "service.json")
				if err := os.WriteFile(target, []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			setTestSecurity(t, target, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", false)
			if err := ensureIdentityDir(path); err == nil {
				t.Fatal("accepted public ACL")
			}
		})
	}
}

func TestWindowsRejectsReparsePathsAndRegularFiles(t *testing.T) {
	requireElevatedWindows(t)
	enableTestPrivilege(t, "SeCreateSymbolicLinkPrivilege")
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := ensureIdentityDir(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(link, "identity")} {
		if err := ensureIdentityDir(path); err == nil {
			t.Fatalf("accepted reparse path %q", path)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "identity")); !os.IsNotExist(err) {
		t.Fatal("wrote through untrusted reparse path")
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(file); err == nil {
		t.Fatal("accepted file as directory")
	}
	if err := os.Symlink(file, filepath.Join(target, "service.json")); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(target); err == nil {
		t.Fatal("accepted linked identity file")
	}
}

func TestWindowsRejectsAncestorThatCanDeleteProtectedChildren(t *testing.T) {
	requireElevatedWindows(t)
	root := t.TempDir()
	path := filepath.Join(root, "identity")
	if err := ensureIdentityDir(path); err != nil {
		t.Fatal(err)
	}
	setTestSecurity(t, root, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x40;;;BU)", false)
	if err := ensureIdentityDir(path); err == nil {
		t.Fatal("accepted ancestor granting delete-child")
	}
}

// Optional lab acceptance probes. Neither prints nor alters existing credentials.
func TestWindowsExistingInstallationTrust(t *testing.T) {
	path := os.Getenv("RCON_TEST_EXISTING_IDENTITY_DIR")
	if path == "" {
		t.Skip("set RCON_TEST_EXISTING_IDENTITY_DIR for an installed-identity compatibility check")
	}
	requireElevatedWindows(t)
	if _, err := loadWindowsServiceConfig(path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDeviceCertificate(path); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsRejectsUserCreatedDirectory(t *testing.T) {
	path := os.Getenv("RCON_TEST_USER_OWNED_DIR")
	if path == "" {
		t.Skip("set RCON_TEST_USER_OWNED_DIR to a directory created by a non-admin account")
	}
	requireElevatedWindows(t)
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || trustedWindowsSID(owner) {
		t.Fatal("fixture must have an untrusted owner")
	}
	if err := ensureIdentityDir(path); err == nil {
		t.Fatal("accepted user-created directory")
	}
	if _, err := os.Stat(filepath.Join(path, "service.json")); !os.IsNotExist(err) {
		t.Fatal("unexpected service configuration in rejected directory")
	}
}

func TestWindowsAllowsProgramDataStyleAncestor(t *testing.T) {
	requireElevatedWindows(t)
	root := t.TempDir()
	// Default ProgramData Users grants: read/traverse + create/write attributes,
	// without delete, delete-child, write-owner or write-DACL.
	setTestSecurity(t, root, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)", false)
	path := filepath.Join(root, "protected-app", "identity")
	if err := ensureIdentityDir(path); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(path); err != nil {
		t.Fatalf("safe reuse: %v", err)
	}
}

func TestWindowsRejectsPublicInheritableACL(t *testing.T) {
	requireElevatedWindows(t)
	path := t.TempDir()
	setTestSecurity(t, path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FR;;;BU)", false)
	if err := ensureIdentityDir(path); err == nil {
		t.Fatal("accepted public inheritance on private directory")
	}
}
