package privsep

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	lastlogEntrySize = 292
	maxMotdSize      = 64 * 1024
)

func readMotd(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMotdSize))
	if err != nil {
		return ""
	}
	return string(data)
}

func readLastLog(path string, uid uint32) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	offset := int64(uid) * lastlogEntrySize
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	entry := make([]byte, lastlogEntrySize)
	if _, err := io.ReadFull(f, entry); err != nil {
		return ""
	}
	seconds := int32(binary.LittleEndian.Uint32(entry[0:4]))
	if seconds <= 0 {
		return ""
	}
	host := cString(entry[36:292])
	when := time.Unix(int64(seconds), 0).Format("Mon Jan _2 15:04:05 2006")
	if host == "" {
		return fmt.Sprintf("Last login: %s\n", when)
	}
	return fmt.Sprintf("Last login: %s from %s\n", when, host)
}

func cString(data []byte) string {
	if i := strings.IndexByte(string(data), 0); i >= 0 {
		data = data[:i]
	}
	return strings.TrimSpace(string(data))
}
