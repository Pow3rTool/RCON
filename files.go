// RCON file primitives — ported from reference/exec_daemon.py to retire it.
// read · edit · write, with the read-before-write hash guard (optimistic
// concurrency: an edit/write must present the sha256 a prior read returned, so
// concurrent agents/humans can't silently clobber each other).
//
// This chunk: `read` (the foundation — its hash is what edit/write check).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxReadBytes     = 10 << 20 // largest file we'll read/hash (10 MB)
	readMaxChars     = 500_000  // hard ceiling on a single /read payload
	defaultReadLimit = 2000     // lines returned when `limit` is omitted
)

// shaBytes returns the sha256 (hex) of a byte slice — the concurrency token.
func shaBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// editFile: POST /edit {path, old_string, new_string, replace_all?, expected_hash?}
//   -> {ok, replacements, hash}   409 stale (hash drift) | 409 ambiguous | 422 not-found
// The read-before-write hash guard: if expected_hash is given and the file has
// changed since, refuse (409 stale) so concurrent edits can't silently clobber.
func editFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path       string `json:"path"`
		OldString  *string `json:"old_string"`
		NewString  *string `json:"new_string"`
		ReplaceAll bool   `json:"replace_all"`
		Expected   string `json:"expected_hash"`
		Rid        string `json:"rid"` // XConnect correlation id (cross-ref to Witchhunt)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON body: " + err.Error()})
		return
	}
	if body.Path == "" || body.OldString == nil || body.NewString == nil {
		writeJSON(w, 400, map[string]any{"error": "path, old_string, new_string required"})
		return
	}
	old, nw := *body.OldString, *body.NewString
	if old == nw {
		writeJSON(w, 400, map[string]any{"error": "old_string and new_string are identical"})
		return
	}
	info, err := os.Stat(body.Path)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "not found", "path": body.Path})
		return
	}
	if info.IsDir() {
		writeJSON(w, 400, map[string]any{"error": "path is a directory"})
		return
	}
	if info.Size() > maxReadBytes {
		writeJSON(w, 413, map[string]any{"error": "file too large for safe edit"})
		return
	}
	raw, err := os.ReadFile(body.Path)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if probeNUL(raw) {
		writeJSON(w, 400, map[string]any{"error": "binary file; refusing to edit"})
		return
	}
	cur := shaBytes(raw)
	if body.Expected != "" && body.Expected != cur {
		writeJSON(w, 409, map[string]any{"error": "stale", "current_hash": cur,
			"message": "file changed since read; re-read before editing"})
		return
	}
	text := string(raw)
	count := strings.Count(text, old)
	if count == 0 {
		writeJSON(w, 422, map[string]any{"error": "old_string not found", "path": body.Path})
		return
	}
	if count > 1 && !body.ReplaceAll {
		writeJSON(w, 409, map[string]any{"matches": count,
			"error": fmt.Sprintf("old_string matches %d places; add surrounding context to make it unique, or pass replace_all=true", count)})
		return
	}
	var out []byte
	reps := 1
	if body.ReplaceAll {
		out = []byte(strings.ReplaceAll(text, old, nw))
		reps = count
	} else {
		out = []byte(strings.Replace(text, old, nw, 1))
	}
	if err := os.WriteFile(body.Path, out, info.Mode().Perm()); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	auditRecord("edit", body.Path, 0, 0, body.Rid)
	writeJSON(w, 200, map[string]any{"ok": true, "path": body.Path, "replacements": reps, "hash": shaBytes(out)})
}

// writeFile: POST /write {path, content, expected_hash?, force?, make_dirs?}
//   -> {ok, created, bytes, hash}   409 stale | 409 exists (no proof)
func writeFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path     string  `json:"path"`
		Content  *string `json:"content"`
		Expected string  `json:"expected_hash"`
		Force    bool    `json:"force"`
		MakeDirs bool    `json:"make_dirs"`
		Rid      string  `json:"rid"` // XConnect correlation id (cross-ref to Witchhunt)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON body: " + err.Error()})
		return
	}
	if body.Path == "" || body.Content == nil {
		writeJSON(w, 400, map[string]any{"error": "path and content required"})
		return
	}
	exists := false
	if info, err := os.Stat(body.Path); err == nil && !info.IsDir() {
		exists = true
		cur, _, _ := hashFile(body.Path)
		if body.Expected != "" {
			if body.Expected != cur {
				writeJSON(w, 409, map[string]any{"error": "stale", "current_hash": cur,
					"message": "file changed since read; re-read"})
				return
			}
		} else if !body.Force {
			writeJSON(w, 409, map[string]any{"error": "exists", "current_hash": cur,
				"message": "file exists; provide expected_hash from a read, or set force=true to overwrite blindly"})
			return
		}
	}
	if body.MakeDirs {
		if dir := filepath.Dir(body.Path); dir != "" {
			_ = os.MkdirAll(dir, 0o755)
		}
	}
	out := []byte(*body.Content)
	if err := os.WriteFile(body.Path, out, 0o644); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	auditRecord("write", body.Path, 0, 0, body.Rid)
	writeJSON(w, 200, map[string]any{"ok": true, "path": body.Path,
		"created": !exists, "bytes": len(out), "hash": shaBytes(out)})
}

// probeNUL reports whether the first 8 KB contain a NUL byte (binary heuristic).
func probeNUL(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

// hashFile returns the sha256 (hex) of a file's full contents + its size — the
// token an edit/write must echo back (read-before-write guard).
func hashFile(path string) (string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	return shaBytes(data), len(data), nil
}

// readFile: POST /read {path, offset?, limit?}
//   -> {content(numbered), hash, total_lines, start_line, end_line, bytes, truncated}
// `hash` is over the WHOLE file (not the returned window) so it's a stable
// concurrency token regardless of how much you paged.
func readFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path   string `json:"path"`
		Offset int    `json:"offset"` // 1-based start line (default 1)
		Limit  int    `json:"limit"`  // max lines (default defaultReadLimit)
		Rid    string `json:"rid"`    // XConnect correlation id (cross-ref to Witchhunt)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid JSON body: " + err.Error()})
		return
	}
	if body.Path == "" {
		writeJSON(w, 400, map[string]any{"error": "path required"})
		return
	}
	info, err := os.Stat(body.Path)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	if info.IsDir() {
		writeJSON(w, 400, map[string]any{"error": "path is a directory"})
		return
	}
	if info.Size() > maxReadBytes {
		writeJSON(w, 413, map[string]any{
			"error": fmt.Sprintf("file too large to read/hash (%d > %d bytes)", info.Size(), maxReadBytes)})
		return
	}
	data, err := os.ReadFile(body.Path)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	lines := strings.Split(string(data), "\n")
	// A trailing newline yields a final "" element — drop it from the count.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	total := len(lines)

	start := body.Offset
	if start < 1 {
		start = 1
	}
	limit := body.Limit
	if limit <= 0 {
		limit = defaultReadLimit
	}
	end := start + limit - 1
	if end > total {
		end = total
	}

	var b strings.Builder
	truncated := false
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%6d\t%s\n", i, lines[i-1]) // cat -n style: number TAB line
		if b.Len() > readMaxChars {
			b.WriteString("… [payload truncated — narrow with offset/limit]\n")
			truncated = true
			end = i
			break
		}
	}
	auditRecord("read", body.Path, 0, 0, body.Rid)
	writeJSON(w, 200, map[string]any{
		"path": body.Path, "hash": hash, "bytes": len(data),
		"total_lines": total, "start_line": start, "end_line": end,
		"truncated": truncated, "content": b.String(),
	})
}
