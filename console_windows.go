// Console helpers for the interactive (double-click) installer.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// launchedFromExplorer is true when this process owns its console alone, which
// is what a double-click produces. Run from an existing shell, the shell is
// attached to the same console too.
func launchedFromExplorer() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

func stdinIsConsole() bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil
}

var stdinReader = bufio.NewReader(os.Stdin)

func promptLine(label string) (string, error) {
	fmt.Print(label)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// promptSecret reads a line with console echo turned off, so a join token
// never appears on screen or in shell history.
func promptSecret(label string) (string, error) {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return "", fmt.Errorf("a console is required to enter the join token: %w", err)
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", err
	}
	defer windows.SetConsoleMode(h, mode)
	s, err := promptLine(label)
	fmt.Println()
	return s, err
}

// relaunchElevated asks UAC to start this executable again as Administrator.
func relaunchElevated(args string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL)
}

// pauseBeforeExit keeps a double-clicked console window open long enough to read.
func pauseBeforeExit() {
	fmt.Print("\nPress Enter to close this window.")
	_, _ = stdinReader.ReadString('\n')
}
