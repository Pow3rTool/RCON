package main

import (
	"os"
	"path/filepath"
)

// replaceFileAtomic writes data to a synced temp file beside path and renames it
// over path, so a crash or kill leaves either the old content or the new, never a
// truncated mix. The temp file is created in the same directory, so on Windows it
// inherits that directory's (protected) DACL.
func replaceFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rcon-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
