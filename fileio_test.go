package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func callFileAPI(t *testing.T, handler http.HandlerFunc, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest("POST", "/", bytes.NewReader(b)))
	return w
}

func TestFileAPIRoundTripAndStaleGuards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "parent", "file.txt")
	write := func(body map[string]any, want int) {
		t.Helper()
		body["path"] = path
		w := callFileAPI(t, writeFile, body)
		if w.Code != want {
			t.Fatalf("write = %d: %s", w.Code, w.Body)
		}
	}
	write(map[string]any{"content": "hello world\n", "make_dirs": true}, 200)
	read := callFileAPI(t, readFile, map[string]any{"path": path})
	if read.Code != 200 {
		t.Fatalf("read = %d: %s", read.Code, read.Body)
	}
	var result struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Hash != shaBytes([]byte("hello world\n")) {
		t.Fatal("incorrect read hash")
	}
	write(map[string]any{"content": "unproved"}, 409)
	write(map[string]any{"content": "stale", "expected_hash": "wrong", "force": true}, 409)
	w := callFileAPI(t, editFile, map[string]any{"path": path, "old_string": "world", "new_string": "x", "expected_hash": result.Hash})
	if w.Code != 200 {
		t.Fatalf("edit = %d: %s", w.Code, w.Body)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "hello x\n" {
		t.Fatalf("edit result: %q, %v", data, err)
	}
	write(map[string]any{"content": "z", "force": true}, 200)
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "z" {
		t.Fatalf("write did not truncate: %q, %v", data, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	write(map[string]any{"content": "stale", "expected_hash": result.Hash}, 409)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("stale write recreated missing file")
	}
}

func TestFileAPIBoundsReadsAndHashChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxReadBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, handler := range []http.HandlerFunc{readFile, editFile, writeFile} {
		w := callFileAPI(t, handler, map[string]any{"path": path, "old_string": "a", "new_string": "b", "content": "overwrite", "expected_hash": "stale"})
		if w.Code != 413 {
			t.Fatalf("oversized file: %d %s", w.Code, w.Body)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != maxReadBytes+1 {
		t.Fatal("rejected write modified file")
	}
	// Force deliberately skips hashing, but still validates a regular file.
	w := callFileAPI(t, writeFile, map[string]any{"path": path, "content": "new", "force": true})
	if w.Code != 200 {
		t.Fatalf("force: %d %s", w.Code, w.Body)
	}
}

func TestFileAPIRejectsDirectories(t *testing.T) {
	path := t.TempDir()
	for _, handler := range []http.HandlerFunc{readFile, editFile, writeFile} {
		w := callFileAPI(t, handler, map[string]any{"path": path, "old_string": "a", "new_string": "b", "content": "overwrite", "force": true})
		if w.Code == 200 {
			t.Fatal("accepted a directory")
		}
	}
}
