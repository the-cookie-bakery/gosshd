//go:build linux

package privsep

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildWorkerSeccompFilter(t *testing.T) {
	filter := buildWorkerSeccompFilter()
	if len(filter) != 2+2*len(workerDeniedSyscalls) {
		t.Fatalf("filter length=%d", len(filter))
	}
	if filter[0].Code != bpfLd|bpfW|bpfAbs || filter[0].K != 0 {
		t.Fatalf("unexpected first instruction: %+v", filter[0])
	}
	last := filter[len(filter)-1]
	if last.Code != bpfRet|bpfK || last.K != uint32(unix.SECCOMP_RET_ALLOW) {
		t.Fatalf("unexpected final instruction: %+v", last)
	}
	foundExec := false
	for i := 0; i < len(filter)-1; i++ {
		if filter[i].Code == bpfJmp|bpfJeq|bpfK && filter[i].K == uint32(unix.SYS_EXECVE) {
			foundExec = true
			if filter[i+1].K&uint32(unix.SECCOMP_RET_ACTION_FULL) != uint32(unix.SECCOMP_RET_ERRNO) {
				t.Fatalf("execve is not denied: %+v", filter[i+1])
			}
		}
	}
	if !foundExec {
		t.Fatal("execve is not covered by the filter")
	}
}
