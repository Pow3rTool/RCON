package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type fileTarget struct {
	root *os.Root
	name string
}

func newFileTarget(path string) (*fileTarget, error) {
	// Reject network/device namespaces before any filesystem access. A drive
	// letter alone or drive-relative path is ambiguous; require local paths.
	path = strings.ReplaceAll(path, "/", `\`)
	volume := filepath.VolumeName(path)
	if strings.HasPrefix(path, `\`) || (volume != "" && (len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path))) {
		return nil, fmt.Errorf("%w: use a local drive path, not a network or device path", os.ErrInvalid)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volume = filepath.VolumeName(abs)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, fmt.Errorf("%w: local drive required", os.ErrInvalid)
	}
	base := volume + `\`
	name := strings.TrimPrefix(abs, base)
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("%w: ordinary file path required", os.ErrInvalid)
	}
	u, err := windows.UTF16PtrFromString(base)
	if err != nil {
		return nil, err
	}
	switch windows.GetDriveType(u) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_CDROM, windows.DRIVE_RAMDISK:
	default:
		return nil, fmt.Errorf("%w: network or unavailable drives are not supported", os.ErrInvalid)
	}
	// Root resolves components using handles and refuses escaping links, without
	// following UNC/device targets first. A lexical prefix check is insufficient:
	// a local directory may be a junction to a remote share. Absolute symlinks and
	// junctions are deliberately refused; relative links within the drive work.
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	return &fileTarget{root: root, name: name}, nil
}

func (p *fileTarget) Close() error { return p.root.Close() }
func (p *fileTarget) Open(flag int, mode os.FileMode) (*os.File, error) {
	return p.root.OpenFile(p.name, flag, mode)
}
func (p *fileTarget) MakeParents() error { return p.root.MkdirAll(filepath.Dir(p.name), 0o755) }
