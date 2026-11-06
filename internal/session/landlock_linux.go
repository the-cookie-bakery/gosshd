//go:build linux

package session

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cookiengineer/gosshd/internal/privsep"
)

type landlockRulesetAttr struct {
	HandledAccessFS uint64
}

func CheckSandbox() error {
	_, err := landlockABI()
	return err
}

func landlockABI() (int, error) {
	version, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION),
	)
	if errno != 0 {
		return 0, fmt.Errorf("landlock is unavailable: %w", errno)
	}
	if int(version) < 1 {
		return 0, errors.New("landlock ABI is too old")
	}
	return int(version), nil
}

func landlockWriteMask(abi int) uint64 {
	mask := uint64(
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE,
	)
	if abi >= 2 {
		mask |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		mask |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return mask
}

func applySessionSandbox(spec *privsep.SessionSpec) error {
	abi, err := landlockABI()
	if err != nil {
		return err
	}
	mask := landlockWriteMask(abi)
	attr := landlockRulesetAttr{HandledAccessFS: mask}
	ruleset, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("create landlock ruleset: %w", errno)
	}
	fd := int(ruleset)
	defer unix.Close(fd)

	for _, path := range writablePaths(spec) {
		if err := addLandlockRule(fd, path, mask); err != nil {
			return err
		}
	}
	if _, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0); errno != 0 {
		return fmt.Errorf("restrict session with landlock: %w", errno)
	}
	return nil
}

func addLandlockRule(ruleset int, path string, mask uint64) error {
	file, err := os.OpenFile(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open landlock path %s: %w", path, err)
	}
	defer file.Close()
	attr := unix.LandlockPathBeneathAttr{
		Allowed_access: mask,
		Parent_fd:      int32(file.Fd()),
	}
	_, _, errno := syscall.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(ruleset),
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
		uintptr(unsafe.Pointer(&attr)),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("add landlock rule for %s: %w", path, errno)
	}
	return nil
}

func writablePaths(spec *privsep.SessionSpec) []string {
	paths := []string{"/tmp", "/var/tmp", "/dev/shm", "/dev", "/proc"}
	if spec.Home != "" {
		paths = append(paths, spec.Home)
	}
	if spec.Chroot != "" {
		paths = append(paths, spec.Chroot)
	}
	if spec.UID != 0 {
		paths = append(paths, fmt.Sprintf("/run/user/%d", spec.UID))
	}
	seen := map[string]bool{}
	out := paths[:0]
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}
