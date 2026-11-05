//go:build !darwin && !windows

package lockfile

import "os"

func fileCreatedUnix(info os.FileInfo) int64 {
	return info.ModTime().Unix()
}
