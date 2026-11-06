package session

import (
	"fmt"
	"strings"
)

type internalSFTPOptions struct {
	ReadOnly bool
	StartDir string
}

func parseInternalSFTP(command string) (internalSFTPOptions, bool, error) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return internalSFTPOptions{}, true, nil
	}
	if fields[0] != "internal-sftp" {
		return internalSFTPOptions{}, false, nil
	}
	var opts internalSFTPOptions
	for i := 1; i < len(fields); i++ {
		switch fields[i] {
		case "-R":
			opts.ReadOnly = true
		case "-d":
			i++
			if i >= len(fields) {
				return opts, true, fmt.Errorf("-d requires a directory")
			}
			opts.StartDir = fields[i]
		case "-u":
			i++
			if i >= len(fields) {
				return opts, true, fmt.Errorf("-u requires a umask")
			}
		case "-l":
			i++
			if i >= len(fields) {
				return opts, true, fmt.Errorf("-l requires a level")
			}
		case "-e":
			// Logging to stderr is the default; accepted for compatibility.
		default:
			return opts, true, fmt.Errorf("unsupported internal-sftp option %q", fields[i])
		}
	}
	return opts, true, nil
}
