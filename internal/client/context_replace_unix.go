//go:build !windows

package client

import (
	"os"
	"path/filepath"
)

func commitContextFile(temp, path string) error {
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	return syncContextDir(filepath.Dir(path))
}
