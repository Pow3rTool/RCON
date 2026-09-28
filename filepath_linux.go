package main

import (
	"os"
	"path/filepath"
	"syscall"
)

type fileTarget struct{ path string }

func newFileTarget(path string) (*fileTarget, error) { return &fileTarget{path}, nil }
func (p *fileTarget) Close() error                   { return nil }
func (p *fileTarget) Open(flag int, mode os.FileMode) (*os.File, error) {
	// A FIFO must not block before the caller can reject its file type.
	return os.OpenFile(p.path, flag|syscall.O_NONBLOCK, mode)
}
func (p *fileTarget) MakeParents() error { return os.MkdirAll(filepath.Dir(p.path), 0o755) }
