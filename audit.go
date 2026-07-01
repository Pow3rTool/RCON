// RCON local action audit — an INDEPENDENT, node-side, tamper-evident record of
// every action RCON took. The central audit (Witchhunt) is born at XConnect, so
// it can't help if XConnect is the compromised/lying party; this log lives on the
// node itself. Each entry hash-chains to the previous (prev = the last entry's
// hash), so deleting or altering any line breaks the chain and is detectable.
//
// It records WHAT ran + WHEN + the result — NOT who: the OBO principal is known
// only at XConnect/Orthanc. This is deliberately the node's-eye view, to be
// cross-checked against the central log (where the principal lives).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type auditEntry struct {
	TS     string  `json:"ts"`
	Verb   string  `json:"verb"`          // run|job|read|edit|write
	Detail string  `json:"detail"`        // command / path (bounded)
	RC     int     `json:"rc"`            // result code (-1 = n/a, e.g. async job start)
	Dur    float64 `json:"dur,omitempty"` // node-side wall-clock seconds (0 = n/a / not yet known)
	RID    string  `json:"rid,omitempty"` // XConnect per-call correlation id — cross-refs this
	//                                        node's-eye entry to the central Witchhunt row (which
	//                                        holds the WHO). Not the principal: the node never sees it.
	Prev string `json:"prev"` // previous entry's hash — the chain link
	Hash string `json:"hash"` // sha256(prev|ts|verb|detail|rc|dur|rid)
}

type auditor struct {
	mu   sync.Mutex
	path string
	head string // last entry's hash (chain head)
	cap  int64  // rotate when the file exceeds this
}

const auditDetailMax = 4096

var theAuditor *auditor

// initAudit opens (or resumes) the chained log at path. Resuming seeds the chain
// head from the last entry's hash so the chain is continuous across restarts.
func initAudit(path string) {
	a := &auditor{path: path, head: "genesis", cap: 64 << 20}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("audit: cannot create %s (%v) — local audit DISABLED", filepath.Dir(path), err)
		return
	}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
		var last auditEntry
		if json.Unmarshal(lines[len(lines)-1], &last) == nil && last.Hash != "" {
			a.head = last.Hash
		}
	}
	theAuditor = a
	log.Printf("audit: local tamper-evident log at %s", path)
}

// auditRecord appends one chained entry. No-op if audit is disabled. Best-effort:
// a write failure is logged but never blocks the action. dur is the node-side
// wall-clock seconds the action took (0 when n/a — e.g. an async job's start
// record, before it has run); rid is XConnect's correlation id (empty for a
// locally-driven action), included so an operator can line a node entry up with
// its central Witchhunt row.
func auditRecord(verb, detail string, rc int, dur float64, rid string) {
	a := theAuditor
	if a == nil {
		return
	}
	if len(detail) > auditDetailMax {
		detail = detail[:auditDetailMax] + "…"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Rotate at the cap (chain restarts in the fresh file; .1 preserves history).
	if fi, err := os.Stat(a.path); err == nil && fi.Size() > a.cap {
		_ = os.Rename(a.path, a.path+".1")
		a.head = "genesis"
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	durStr := strconv.FormatFloat(dur, 'f', 3, 64)
	e := auditEntry{TS: ts, Verb: verb, Detail: detail, RC: rc, Dur: dur, RID: rid, Prev: a.head}
	sum := sha256.Sum256([]byte(e.Prev + "|" + ts + "|" + verb + "|" + detail + "|" +
		strconv.Itoa(rc) + "|" + durStr + "|" + rid))
	e.Hash = hex.EncodeToString(sum[:])
	line, _ := json.Marshal(e)
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit: open %s: %v", a.path, err)
		return
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
	a.head = e.Hash
}
