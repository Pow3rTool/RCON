package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

var errFileTooLarge = errors.New("file too large to read/hash (maximum 10 MB)")

func openRegularFile(path string, flag int) (*os.File, error) {
	p, err := newFileTarget(path)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	return p.OpenRegular(flag)
}

// Never open with O_TRUNC: validate the actual opened object before modifying it.
func (p *fileTarget) OpenRegular(flag int) (*os.File, error) {
	f, err := p.Open(flag, 0o644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("%w: path must be a regular file", os.ErrInvalid)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func readBoundedFile(f *os.File) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxReadBytes {
		return nil, errFileTooLarge
	}
	// Stat is only a fast rejection: a file can grow during the read.
	data, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if len(data) > maxReadBytes {
		return nil, errFileTooLarge
	}
	return data, err
}

func replaceOpenedFile(f *os.File, data []byte) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Truncate(int64(len(data)))
}

func fileError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, errFileTooLarge):
		code = http.StatusRequestEntityTooLarge
	case errors.Is(err, os.ErrInvalid):
		code = http.StatusBadRequest
	case os.IsNotExist(err):
		code = http.StatusNotFound
	case os.IsExist(err):
		code = http.StatusConflict
	case os.IsPermission(err):
		code = http.StatusForbidden
	}
	writeJSON(w, code, map[string]any{"error": err.Error()})
}
