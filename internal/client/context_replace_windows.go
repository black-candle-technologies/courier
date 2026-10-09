//go:build windows

package client

import "golang.org/x/sys/windows"

// Directory File.Sync is unavailable on Windows. Use the platform's
// write-through replacement for the binding ledger. Full directory migration
// remains gated independently until its Windows recovery matrix is validated.
func commitContextFile(temp, path string) error {
	from, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
