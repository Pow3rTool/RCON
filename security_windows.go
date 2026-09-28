package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const protectedDirectorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// Owners can replace DACLs. Never adopt a path or key owned by a normal user,
// even if its current DACL appears restrictive. TrustedInstaller owns standard
// Windows ancestors; it is not an interactive/user-writable principal.
func trustedWindowsSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	switch sid.String() {
	case "S-1-5-18", "S-1-5-32-544",
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
		return true
	}
	return false
}

func validateWindowsSecurity(sd *windows.SECURITY_DESCRIPTOR, private bool) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !trustedWindowsSID(owner) {
		return fmt.Errorf("untrusted owner; use an Administrator-owned directory/key")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("missing DACL")
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return err
		}
		if !private && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported ACL entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trustedWindowsSID(sid) {
			continue
		}
		// Ancestors may allow creating new children (e.g. ProgramData), but
		// must not let untrusted users change trust or remove our protected child.
		danger := uint32(windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE |
			0x40 /* FILE_DELETE_CHILD */ | windows.GENERIC_ALL)
		if private {
			danger = ^uint32(0)
		}
		if uint32(ace.Mask)&danger != 0 {
			return fmt.Errorf("DACL grants untrusted access")
		}
	}
	return nil
}

func openTrustedPath(path string, private, directory bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	// Metadata-only handles do not enforce the share exclusions below. A data
	// access bit is required (FILE_READ_DATA is FILE_LIST_DIRECTORY for dirs).
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_DATA)
	if private && directory {
		access |= windows.WRITE_DAC
	}
	// Do not follow reparse points or permit concurrent rename/delete while
	// establishing trust from the volume root down to the protected directory.
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	if !private {
		// ProgramData normally lets Users add children and write attributes.
		// Hold ancestors without write sharing while creating our protected
		// child: an empty ancestor cannot become a reparse point mid-walk.
		// Afterwards the protected child cannot be deleted by Users, keeping
		// the ancestor nonempty (NTFS refuses reparsing nonempty directories).
		// https://learn.microsoft.com/windows/win32/fileio/reparse-points
		share = windows.FILE_SHARE_READ
	}
	h, err := windows.CreateFile(p, access, share, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(h)
		}
	}()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return 0, fmt.Errorf("reparse points are not permitted")
	}
	if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return 0, fmt.Errorf("unexpected file type")
	}
	if !directory && info.NumberOfLinks != 1 {
		return 0, fmt.Errorf("hard-linked identity files are not permitted")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	if err := validateWindowsSecurity(sd, private); err != nil {
		return 0, err
	}
	ok = true
	return h, nil
}

func ensureIdentityDir(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(path)
	// Local drive paths only: network shares and device namespaces have different
	// trust semantics. Reject a drive root itself as an identity directory.
	if len(volume) != 2 || volume[1] != ':' || path == volume+`\` {
		return fmt.Errorf("identity directory must be below a local drive root")
	}
	sd, err := windows.SecurityDescriptorFromString(protectedDirectorySDDL)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	var held []windows.Handle
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			windows.CloseHandle(held[i])
		}
	}()
	current := volume + `\`
	parts := append([]string{""}, strings.Split(strings.TrimPrefix(path, current), `\`)...)
	for i, part := range parts {
		if i > 0 {
			current = filepath.Join(current, part)
		}
		private := i == len(parts)-1
		if i > 0 {
			p, err := windows.UTF16PtrFromString(current)
			if err != nil {
				return err
			}
			// Create with the final protected owner/DACL, never a permissive
			// MkdirAll followed by hardening. Existing paths must pass validation.
			err = windows.CreateDirectory(p, &sa)
			if err != nil && err != windows.ERROR_ALREADY_EXISTS {
				return fmt.Errorf("create protected directory %q: %w", current, err)
			}
		}
		h, err := openTrustedPath(current, private, true)
		if err != nil {
			return fmt.Errorf("unsafe directory %q: %w", current, err)
		}
		held = append(held, h)
	}
	// A protected parent does not repair unsafe pre-existing children. Refuse
	// links, foreign owners or public ACLs before reading/writing service state.
	err = filepath.WalkDir(path, func(p string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if p == path {
			return nil
		}
		h, err := openTrustedPath(p, true, entry.IsDir())
		if err != nil {
			return fmt.Errorf("unsafe identity entry %q: %w", p, err)
		}
		windows.CloseHandle(h)
		return nil
	})
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(held[len(held)-1], windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
