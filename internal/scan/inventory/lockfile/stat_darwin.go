//go:build darwin

package lockfile

import (
	"os"
	"syscall"
)

func fileCreatedUnix(info os.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Birthtimespec.Sec > 0 {
		return st.Birthtimespec.Sec
	}
	return info.ModTime().Unix()
}
