//go:build !windows

package client

import (
	"os"
	"path/filepath"
)

func renamePublishedFile(from, to string) error { return os.Rename(from, to) }
func syncPublishedDirectory(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
