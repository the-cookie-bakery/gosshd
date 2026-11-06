//go:build linux

package privsep

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	bpfLd  = 0x00
	bpfW   = 0x00
	bpfAbs = 0x20
	bpfJmp = 0x05
	bpfJeq = 0x10
	bpfK   = 0x00
	bpfRet = 0x06
)

var workerDeniedSyscalls = []int{
	unix.SYS_EXECVE,
	unix.SYS_EXECVEAT,
	unix.SYS_PTRACE,
	unix.SYS_MOUNT,
	unix.SYS_UMOUNT2,
	unix.SYS_PIVOT_ROOT,
	unix.SYS_CHROOT,
	unix.SYS_SETUID,
	unix.SYS_SETGID,
	unix.SYS_SETREUID,
	unix.SYS_SETREGID,
	unix.SYS_SETRESUID,
	unix.SYS_SETRESGID,
	unix.SYS_SETGROUPS,
	unix.SYS_CAPSET,
	unix.SYS_UNSHARE,
	unix.SYS_SETNS,
	unix.SYS_BPF,
	unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_KEYCTL,
	unix.SYS_ADD_KEY,
	unix.SYS_REQUEST_KEY,
	unix.SYS_INIT_MODULE,
	unix.SYS_FINIT_MODULE,
	unix.SYS_DELETE_MODULE,
	unix.SYS_KEXEC_LOAD,
	unix.SYS_KEXEC_FILE_LOAD,
	unix.SYS_REBOOT,
	unix.SYS_SWAPON,
	unix.SYS_SWAPOFF,
}

func applyWorkerSandbox() error {
	filter := buildWorkerSeccompFilter()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno := syscall.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&program)),
	)
	if errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	return nil
}

func buildWorkerSeccompFilter() []unix.SockFilter {
	filter := make([]unix.SockFilter, 0, 2+2*len(workerDeniedSyscalls))
	filter = append(filter, unix.SockFilter{Code: bpfLd | bpfW | bpfAbs, K: 0})
	for _, nr := range workerDeniedSyscalls {
		filter = append(filter,
			unix.SockFilter{Code: bpfJmp | bpfJeq | bpfK, Jt: 0, Jf: 1, K: uint32(nr)},
			unix.SockFilter{Code: bpfRet | bpfK, K: uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))},
		)
	}
	filter = append(filter, unix.SockFilter{Code: bpfRet | bpfK, K: uint32(unix.SECCOMP_RET_ALLOW)})
	return filter
}
