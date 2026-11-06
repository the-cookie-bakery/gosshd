package privsep

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCapWords(t *testing.T) {
	words := capWords([]int{unix.CAP_SETUID, unix.CAP_DAC_OVERRIDE, unix.CAP_SYS_CHROOT})
	if words[0]&(1<<uint(unix.CAP_SETUID)) == 0 {
		t.Fatal("CAP_SETUID missing")
	}
	if words[0]&(1<<uint(unix.CAP_DAC_OVERRIDE)) == 0 {
		t.Fatal("CAP_DAC_OVERRIDE missing")
	}
	if words[0]&(1<<uint(unix.CAP_SYS_CHROOT)) == 0 {
		t.Fatal("CAP_SYS_CHROOT missing")
	}
	if words[0]&(1<<uint(unix.CAP_SYS_ADMIN)) != 0 {
		t.Fatal("CAP_SYS_ADMIN unexpectedly set")
	}
}

func TestDropMonitorCapabilitiesAllThreads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := DropMonitorCapabilities(); err != nil {
		if errors.Is(err, syscall.ENOTSUP) {
			t.Skip("AllThreadsSyscall unavailable with cgo")
		}
		t.Fatal(err)
	}
	wantEff := capMask(monitorEffectiveCaps)
	wantBnd := capMask(monitorBoundingCaps)
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		eff, bnd, err := readTaskCaps("/proc/self/task/" + entry.Name() + "/status")
		if err != nil {
			t.Fatal(err)
		}
		if eff != wantEff {
			t.Fatalf("thread %s CapEff=%#x want %#x", entry.Name(), eff, wantEff)
		}
		if bnd != wantBnd {
			t.Fatalf("thread %s CapBnd=%#x want %#x", entry.Name(), bnd, wantBnd)
		}
	}
}

func capMask(caps []int) uint64 {
	words := capWords(caps)
	return uint64(words[1])<<32 | uint64(words[0])
}

func readTaskCaps(path string) (uint64, uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var eff, bnd uint64
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "CapEff:"):
			eff = parseCapHex(line)
		case strings.HasPrefix(line, "CapBnd:"):
			bnd = parseCapHex(line)
		}
	}
	return eff, bnd, nil
}

func parseCapHex(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseUint(fields[1], 16, 64)
	if err != nil {
		return 0
	}
	return n
}
