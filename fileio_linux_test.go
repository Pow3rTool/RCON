package main

import (
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFileAPIRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []http.HandlerFunc{readFile, editFile, writeFile} {
		w := callFileAPI(t, handler, map[string]any{"path": path, "old_string": "a", "new_string": "b", "content": "overwrite", "force": true})
		if w.Code != 400 {
			t.Fatalf("special file: %d %s", w.Code, w.Body)
		}
	}
}

func TestFileReplacementKeepsOpenedObject(t *testing.T) {
	dir := t.TempDir()
	path, moved := filepath.Join(dir, "file"), filepath.Join(dir, "moved")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openRegularFile(path, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceOpenedFile(f, []byte("edited")); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{path: "replacement", moved: "edited"} {
		b, err := os.ReadFile(p)
		if err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", p, b, err)
		}
	}
}
