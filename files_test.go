package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"syscall"
	"testing"
)

func callWrite(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/write", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	writeFile(rec, req)
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return rec.Code, response
}

func TestParseWriteMode(t *testing.T) {
	valid := map[string]os.FileMode{
		"640":   0o640,
		"0640":  0o640,
		"0o640": 0o640,
		"0000":  0,
		"777":   0o777,
	}
	for raw, want := range valid {
		t.Run("valid-"+raw, func(t *testing.T) {
			got, set, err := parseWriteMode(raw)
			if err != nil || !set || got != want {
				t.Fatalf("parseWriteMode(%q) = %04o, %v, %v; want %04o, true, nil",
					raw, got, set, err, want)
			}
		})
	}

	for _, raw := range []string{"64", "06400", "4755", "0o4755", "08x", "-1"} {
		t.Run("invalid-"+raw, func(t *testing.T) {
			if _, _, err := parseWriteMode(raw); err == nil {
				t.Fatalf("parseWriteMode(%q) unexpectedly succeeded", raw)
			}
		})
	}

	if got, set, err := parseWriteMode(""); err != nil || set || got != 0 {
		t.Fatalf("empty mode = %04o, %v, %v; want zero, false, nil", got, set, err)
	}
}

func TestWriteFileCreatesWithExplicitModeAndReportsMetadata(t *testing.T) {
	path := t.TempDir() + "/nested/service.conf"
	code, response := callWrite(t, map[string]any{
		"path": path, "content": "secret=true\n", "make_dirs": true, "mode": "0600",
	})
	if code != http.StatusOK {
		t.Fatalf("status %d: %#v", code, response)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret=true\n" {
		t.Fatalf("content = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o; want 0600", got)
	}
	if response["mode"] != "0600" {
		t.Fatalf("response mode = %#v; want 0600", response["mode"])
	}
	if response["created"] != true {
		t.Fatalf("created = %#v; want true", response["created"])
	}
	st := info.Sys().(*syscall.Stat_t)
	if response["uid"] != float64(st.Uid) || response["gid"] != float64(st.Gid) {
		t.Fatalf("response ownership = (%#v,%#v); want (%d,%d)",
			response["uid"], response["gid"], st.Uid, st.Gid)
	}
}

func TestWriteFilePreservesExistingModeWhenOmitted(t *testing.T) {
	path := t.TempDir() + "/existing.conf"
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, _, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code, response := callWrite(t, map[string]any{
		"path": path, "content": "new\n", "expected_hash": hash,
	})
	if code != http.StatusOK {
		t.Fatalf("status %d: %#v", code, response)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o; want preserved 0600", got)
	}
}

func TestWriteFileRejectsMetadataBeforeChangingContent(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "special-mode-bits", field: "mode", value: "4755"},
		{name: "unknown-owner", field: "owner", value: "rcon-no-such-owner-for-test"},
		{name: "unknown-group", field: "group", value: "rcon-no-such-group-for-test"},
		{name: "owner-overflow", field: "owner", value: "99999999999999999999"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir() + "/guarded"
			if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{"path": path, "content": "new\n", "force": true, tc.field: tc.value}
			code, response := callWrite(t, body)
			if code != http.StatusBadRequest {
				t.Fatalf("status %d: %#v", code, response)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "old\n" {
				t.Fatalf("invalid metadata changed content to %q", data)
			}
		})
	}
}

func TestWriteFileAppliesNumericOwnershipAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("successful chown requires root")
	}
	path := t.TempDir() + "/owned"
	code, response := callWrite(t, map[string]any{
		"path":    path,
		"content": "owned\n",
		"owner":   strconv.Itoa(os.Getuid()),
		"group":   strconv.Itoa(os.Getgid()),
		"mode":    "0640",
	})
	if code != http.StatusOK {
		t.Fatalf("status %d: %#v", code, response)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) {
		t.Fatalf("ownership = %d:%d; want %d:%d", st.Uid, st.Gid, os.Getuid(), os.Getgid())
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode = %04o; want 0640", got)
	}
	hash, ok := response["hash"].(string)
	if !ok || len(hash) != 64 {
		t.Fatalf("write response hash = %#v; want 64 hex characters", response["hash"])
	}
}

func TestMuxExposesFailClosedWriteMetadataEndpoint(t *testing.T) {
	path := t.TempDir() + "/metadata.conf"
	raw, err := json.Marshal(map[string]any{
		"path": path, "content": "private=true\n", "mode": "0600",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/write-metadata", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	mux("test-svid", NewJobStore(), t.TempDir(), "127.0.0.1:3").ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o; want 0600", got)
	}
}
