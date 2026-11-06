package privsep

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var monitorEffectiveCaps = []int{
	unix.CAP_DAC_OVERRIDE,
	unix.CAP_KILL,
	unix.CAP_SETUID,
	unix.CAP_SETGID,
	unix.CAP_SETPCAP,
}

var monitorBoundingCaps = []int{
	unix.CAP_DAC_OVERRIDE,
	unix.CAP_SETUID,
	unix.CAP_SETGID,
	unix.CAP_SYS_CHROOT,
}

func DropMonitorCapabilities() error {
	if os.Geteuid() != 0 {
		return nil
	}
	// Reduce permitted/effective first, while the bounding set is still full.
	// The bounding set is reduced afterwards; dropping from the bounding set
	// does not clear capabilities that are already permitted.
	if err := setEffectiveCaps(monitorEffectiveCaps); err != nil {
		return fmt.Errorf("set monitor capabilities: %w", err)
	}
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		if containsCap(monitorBoundingCaps, cap) {
			continue
		}
		if err := dropBoundingCap(cap); err != nil {
			return fmt.Errorf("drop bounding capability %d: %w", cap, err)
		}
	}
	return nil
}

func dropBoundingCap(cap int) error {
	_, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, uintptr(unix.PR_CAPBSET_DROP), uintptr(cap), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func setEffectiveCaps(caps []int) error {
	words := capWords(caps)
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: words[0], Permitted: words[0]},
		{Effective: words[1], Permitted: words[1]},
	}
	_, _, errno := syscall.AllThreadsSyscall6(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&header)),
		uintptr(unsafe.Pointer(&data[0])),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func capWords(caps []int) [2]uint32 {
	var words [2]uint32
	for _, cap := range caps {
		if cap < 0 || cap > 63 {
			continue
		}
		words[cap/32] |= 1 << (uint(cap) % 32)
	}
	return words
}

func containsCap(caps []int, want int) bool {
	for _, cap := range caps {
		if cap == want {
			return true
		}
	}
	return false
}
