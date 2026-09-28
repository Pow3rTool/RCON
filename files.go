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
	"os/user"
	"strconv"
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
//
//	-> {ok, replacements, hash}   409 stale (hash drift) | 409 ambiguous | 422 not-found
//
// The read-before-write hash guard: if expected_hash is given and the file has
// changed since, refuse (409 stale) so concurrent edits can't silently clobber.
func editFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path       string  `json:"path"`
		OldString  *string `json:"old_string"`
		NewString  *string `json:"new_string"`
		ReplaceAll bool    `json:"replace_all"`
		Expected   string  `json:"expected_hash"`
		Rid        string  `json:"rid"` // XConnect correlation id (cross-ref to Witchhunt)
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
	f, err := openRegularFile(body.Path, os.O_RDWR)
	if err != nil {
		fileError(w, err)
		return
	}
	defer f.Close()
	raw, err := readBoundedFile(f)
	if err != nil {
		fileError(w, err)
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
	if err := replaceOpenedFile(f, out); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	auditRecord("edit", body.Path, 0, 0, body.Rid)
	writeJSON(w, 200, map[string]any{"ok": true, "path": body.Path, "replacements": reps, "hash": shaBytes(out)})
}

// parseWriteMode accepts the familiar file-mode spellings used by operators:
// "640", "0640", or "0o640". Only the nine permission bits are accepted;
// setuid/setgid/sticky bits are deliberately out of scope for this primitive.
func parseWriteMode(raw string) (os.FileMode, bool, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false, nil
	}
	if strings.HasPrefix(s, "0o") {
		s = strings.TrimPrefix(s, "0o")
	}
	if len(s) == 4 && s[0] == '0' {
		s = s[1:]
	}
	if len(s) != 3 {
		return 0, false, fmt.Errorf("mode must be three octal permission digits (for example 0640)")
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, false, fmt.Errorf("mode must be octal (for example 0640)")
		}
	}
	n, err := strconv.ParseUint(s, 8, 9)
	if err != nil {
		return 0, false, fmt.Errorf("invalid mode: %w", err)
	}
	return os.FileMode(n), true, nil
}

// parseLinuxID bounds IDs to the signed 32-bit range accepted consistently by
// the Linux targets RCON supports. -1 is reserved by chown(2) as "unchanged".
func parseLinuxID(raw, kind string) (int, error) {
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 0 {
		return -1, fmt.Errorf("invalid %s id %q", kind, raw)
	}
	return int(n), nil
}

func resolveOwner(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return -1, nil
	}
	if _, err := strconv.ParseUint(s, 10, 64); err == nil {
		return parseLinuxID(s, "owner")
	}
	u, err := user.Lookup(s)
	if err != nil {
		return -1, fmt.Errorf("unknown owner %q", s)
	}
	return parseLinuxID(u.Uid, "owner")
}

func resolveGroup(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return -1, nil
	}
	if _, err := strconv.ParseUint(s, 10, 64); err == nil {
		return parseLinuxID(s, "group")
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return -1, fmt.Errorf("unknown group %q", s)
	}
	return parseLinuxID(g.Gid, "group")
}

// writeFile: POST /write
// {path, content, expected_hash?, force?, make_dirs?, owner?, group?, mode?}
//
//	-> {ok, created, bytes, hash, mode, uid?, gid?}
//	409 stale | 409 exists (no proof)
func writeFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path     string  `json:"path"`
		Content  *string `json:"content"`
		Expected string  `json:"expected_hash"`
		Force    bool    `json:"force"`
		MakeDirs bool    `json:"make_dirs"`
		Owner    string  `json:"owner"`
		Group    string  `json:"group"`
		Mode     string  `json:"mode"`
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
	if !supportsPOSIXMetadata && (body.Owner != "" || body.Group != "" || body.Mode != "") {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "POSIX owner/group/mode are not supported on Windows; use explicit Windows ACL commands"})
		return
	}
	mode, modeSet, err := parseWriteMode(body.Mode)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	uid, err := resolveOwner(body.Owner)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	gid, err := resolveGroup(body.Group)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	p, err := newFileTarget(body.Path)
	if err != nil {
		fileError(w, err)
		return
	}
	defer p.Close()
	f, err := p.OpenRegular(os.O_RDWR)
	exists := err == nil
	if os.IsNotExist(err) {
		if body.Expected != "" {
			writeJSON(w, 409, map[string]any{"error": "stale", "message": "file no longer exists; re-read"})
			return
		}
		if body.MakeDirs {
			if err := p.MakeParents(); err != nil {
				fileError(w, err)
				return
			}
		}
		// A file appearing after the first open must not be overwritten blindly.
		f, err = p.OpenRegular(os.O_RDWR | os.O_CREATE | os.O_EXCL)
	}
	if err != nil {
		fileError(w, err)
		return
	}
	defer f.Close()
	if exists && (body.Expected != "" || !body.Force) {
		raw, err := readBoundedFile(f)
		if err != nil {
			fileError(w, err)
			return
		}
		cur := shaBytes(raw)
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
	out := []byte(*body.Content)
	if err := replaceOpenedFile(f, out); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// Apply ownership before an explicit mode: chown can clear set-id bits on
	// Linux, and this ordering guarantees the requested final permission bits.
	if uid != -1 || gid != -1 {
		if err := f.Chown(uid, gid); err != nil {
			auditRecord("write", body.Path, 1, 0, body.Rid)
			writeJSON(w, 500, map[string]any{"error": "apply ownership: " + err.Error(),
				"content_written": true})
			return
		}
	}
	if modeSet {
		if err := f.Chmod(mode); err != nil {
			auditRecord("write", body.Path, 1, 0, body.Rid)
			writeJSON(w, 500, map[string]any{"error": "apply mode: " + err.Error(),
				"content_written": true})
			return
		}
	}
	info, err := f.Stat()
	if err != nil {
		auditRecord("write", body.Path, 1, 0, body.Rid)
		writeJSON(w, 500, map[string]any{"error": "stat written file: " + err.Error(),
			"content_written": true})
		return
	}
	response := map[string]any{"ok": true, "path": body.Path,
		"created": !exists, "bytes": len(out), "hash": shaBytes(out),
		"mode": fmt.Sprintf("%04o", info.Mode().Perm())}
	addFileMetadata(response, info)
	auditRecord("write", body.Path, 0, 0, body.Rid)
	writeJSON(w, 200, response)
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
	f, err := openRegularFile(path, os.O_RDONLY)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	data, err := readBoundedFile(f)
	if err != nil {
		return "", 0, err
	}
	return shaBytes(data), len(data), nil
}

// readFile: POST /read {path, offset?, limit?}
//
//	-> {content(numbered), hash, total_lines, start_line, end_line, bytes, truncated}
//
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
	f, err := openRegularFile(body.Path, os.O_RDONLY)
	if err != nil {
		fileError(w, err)
		return
	}
	defer f.Close()
	data, err := readBoundedFile(f)
	if err != nil {
		fileError(w, err)
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
