package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsFileAPIRejectsNetworkAndDevicePaths(t *testing.T) {
	for _, path := range []string{
		`\\localhost\share\file`, `//localhost/share/file`,
		`\\?\UNC\localhost\share\file`, `\\.\PhysicalDrive0`,
		`\??\C:\file`, `\\?\C:\file`, `C:relative`,
		`C:\NUL`, `C:\CON.txt`, `C:\COM1`, `C:\file:stream`,
	} {
		if p, err := newFileTarget(path); err == nil {
			p.Close()
			t.Fatalf("accepted %q", path)
		}
	}
}

func TestWindowsFileAPIRejectsLinksToNetworkAndAbsolutePaths(t *testing.T) {
	requireElevatedWindows(t)
	enableTestPrivilege(t, "SeCreateSymbolicLinkPrivilege")
	dir := t.TempDir()
	for i, target := range []string{`\\localhost\RCON-no-such-share`, dir} {
		link := filepath.Join(dir, []string{"network", "absolute"}[i])
		// Direct API avoids os.Symlink probing the target to determine its type.
		if err := windows.CreateSymbolicLink(utf16(link), utf16(target), windows.SYMBOLIC_LINK_FLAG_DIRECTORY); err != nil {
			t.Fatal(err)
		}
		for _, handler := range []http.HandlerFunc{readFile, editFile, writeFile} {
			w := callFileAPI(t, handler, map[string]any{"path": filepath.Join(link, "child", "file.txt"), "old_string": "a", "new_string": "b", "content": "overwrite", "force": true, "make_dirs": true})
			if w.Code == 200 || !strings.Contains(w.Body.String(), "path escapes from parent") {
				t.Fatalf("link was not rejected by rooted path resolution: %d %s", w.Code, w.Body)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "child")); !os.IsNotExist(err) {
		t.Fatal("created directory through an absolute link")
	}
}

func TestWindowsFileAPIRelativeLinkWithinDrive(t *testing.T) {
	requireElevatedWindows(t)
	enableTestPrivilege(t, "SeCreateSymbolicLinkPrivilege")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "target.txt"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "relative.txt")
	if err := windows.CreateSymbolicLink(utf16(link), utf16("target.txt"), 0); err != nil {
		t.Fatal(err)
	}
	w := callFileAPI(t, readFile, map[string]any{"path": link})
	if w.Code != 200 {
		t.Fatalf("relative local link: %d %s", w.Code, w.Body)
	}
}
