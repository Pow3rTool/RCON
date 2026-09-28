package main

import (
	"bytes"
	"os/exec"
	"sync"
)

// Every shell owns a process tree; cancelling must terminate descendants too.
type processTree interface {
	Started(*exec.Cmd) error
	Kill() error
	Cancel() error
	Close()
}

// Bound memory while the process writes, not only when serializing its output.
type cappedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(p) > b.limit-b.buf.Len() {
		p = p[:b.limit-b.buf.Len()]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return n, nil
}
func (b *cappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}
