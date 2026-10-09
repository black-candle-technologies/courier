package client

import "golang.org/x/sys/windows"

// WRITE_THROUGH waits for publication to reach storage; os.File.Sync on a
// directory is unsupported on Windows. The temporary file is synced first.
func renamePublishedFile(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func syncPublishedDirectory(string) error { return nil }
