package privsep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cookiengineer/gosshd/internal/auth"
)

func testPerms() *auth.Permissions {
	return &auth.Permissions{Username: "alice", UID: 1000, Home: "/home/alice"}
}

func TestExpandChrootTokens(t *testing.T) {
	got, err := expandChrootTokens("/srv/%u/%h/%U/%%", testPerms())
	if err != nil {
		t.Fatal(err)
	}
	if got != "/srv/alice//home/alice/1000/%" {
		t.Fatalf("got %q", got)
	}
	if _, err := expandChrootTokens("/srv/%x", testPerms()); err == nil {
		t.Fatal("expected unsupported token to be rejected")
	}
}

func TestResolveChrootRejectsRelative(t *testing.T) {
	if _, err := resolveChroot("relative/path", testPerms()); err == nil {
		t.Fatal("expected relative chroot to be rejected")
	}
}

func TestResolveChrootRejectsMissing(t *testing.T) {
	if _, err := resolveChroot("/definitely/not/a/real/gosshd/path", testPerms()); err == nil {
		t.Fatal("expected missing chroot to be rejected")
	}
}

func TestResolveChrootOwnership(t *testing.T) {
	dir := t.TempDir()
	_, err := resolveChroot(dir, testPerms())
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("root-owned temp dir rejected: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("expected non-root-owned chroot to be rejected")
	}
}

func TestResolveChrootRejectsWritableAndSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create root-owned chroot fixtures")
	}
	writable, err := os.MkdirTemp("/", "gosshd-chroot-w-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(writable)
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveChroot(writable, testPerms()); err == nil {
		t.Fatal("expected world-writable chroot to be rejected")
	}

	clean, err := os.MkdirTemp("/", "gosshd-chroot-c-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(clean)
	link := filepath.Join(clean, "link")
	if err := os.Symlink(clean, link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveChroot(link, testPerms()); err == nil {
		t.Fatal("expected symlinked chroot to be rejected")
	}
}
