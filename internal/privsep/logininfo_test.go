package privsep

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadMotd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "motd")
	if err := os.WriteFile(path, []byte("welcome\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readMotd(path); got != "welcome\n" {
		t.Fatalf("motd=%q", got)
	}
	if got := readMotd(filepath.Join(dir, "missing")); got != "" {
		t.Fatalf("missing motd=%q", got)
	}
}

func TestReadLastLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lastlog")
	uid := uint32(1234)
	entry := make([]byte, lastlogEntrySize)
	binary.LittleEndian.PutUint32(entry[0:4], uint32(time.Unix(1700000000, 0).Unix()))
	copy(entry[4:36], []byte("pts/0"))
	copy(entry[36:292], []byte("example.test"))
	data := make([]byte, int(uid+1)*lastlogEntrySize)
	copy(data[int(uid)*lastlogEntrySize:], entry)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got := readLastLog(path, uid)
	if !strings.Contains(got, "example.test") || !strings.Contains(got, "Last login:") {
		t.Fatalf("lastlog=%q", got)
	}
	if got := readLastLog(path, uid+1); got != "" {
		t.Fatalf("empty entry=%q", got)
	}
}
