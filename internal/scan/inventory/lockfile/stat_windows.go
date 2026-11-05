//go:build windows

package lockfile

import (
	"os"
	"syscall"
)

func fileCreatedUnix(info os.FileInfo) int64 {
	if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		if sec := d.CreationTime.Nanoseconds() / 1e9; sec > 0 {
			return sec
		}
	}
	return info.ModTime().Unix()
}
