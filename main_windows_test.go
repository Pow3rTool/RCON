package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Native tests often run on a machine where RCON is installed. Point the whole
// C:\RCON tree at a temporary directory so no test can touch the real service's
// health marker, upgrade journal, lock, or logs.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "rcon-test-root-")
	if err != nil {
		panic(err)
	}
	windowsRoot = root
	for _, d := range []string{"etc", "logs", "state", "releases"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}
