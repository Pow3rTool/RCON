package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Native tests often run on a machine where RCON is installed. Point the whole
// C:\RCON tree at a temporary directory so no test can touch the real service's
// health marker, upgrade journal, lock, or logs.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "pointer-fixture" {
		runtime.LockOSThread()
		if err := runPointerFixture(os.Args[2]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "badge-fixture" {
		runtime.LockOSThread()
		if err := runBadgeFixture(os.Args[2]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "escape-fixture" {
		runtime.LockOSThread()
		if err := runOutsideEscapeFixture(os.Args[2]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "pause-fixture" {
		runtime.LockOSThread()
		if err := runPauseFixture(os.Args[2]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "indicator-fixture" {
		runtime.LockOSThread()
		if err := runIndicatorFixture(os.Args[2]); err != nil {
			panic(err)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "desktop-worker" {
		if err := runDesktopWorker(os.Args[2:]); err != nil {
			panic(err)
		}
		os.Exit(0)
	}
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
