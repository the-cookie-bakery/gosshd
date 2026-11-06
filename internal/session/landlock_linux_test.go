//go:build linux

package session

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLandlockWriteMask(t *testing.T) {
	mask1 := landlockWriteMask(1)
	if mask1&unix.LANDLOCK_ACCESS_FS_WRITE_FILE == 0 {
		t.Fatal("WRITE_FILE missing")
	}
	if mask1&unix.LANDLOCK_ACCESS_FS_REFER != 0 {
		t.Fatal("REFER should require ABI 2")
	}
	if mask1&unix.LANDLOCK_ACCESS_FS_TRUNCATE != 0 {
		t.Fatal("TRUNCATE should require ABI 3")
	}
	mask2 := landlockWriteMask(2)
	if mask2&unix.LANDLOCK_ACCESS_FS_REFER == 0 {
		t.Fatal("REFER missing for ABI 2")
	}
	if mask2&unix.LANDLOCK_ACCESS_FS_TRUNCATE != 0 {
		t.Fatal("TRUNCATE should require ABI 3")
	}
	mask3 := landlockWriteMask(3)
	if mask3&unix.LANDLOCK_ACCESS_FS_TRUNCATE == 0 {
		t.Fatal("TRUNCATE missing for ABI 3")
	}
}
