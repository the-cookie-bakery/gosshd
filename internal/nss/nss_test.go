package nss

import (
	"os/user"
	"strconv"
	"testing"
)

func TestLookupCurrentUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("current user unavailable: %v", err)
	}
	u, err := LookupUser(current.Username)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := strconv.ParseUint(current.Uid, 10, 32)
	if u.UID != uint32(want) {
		t.Fatalf("UID=%d want %d", u.UID, want)
	}
	if u.Name != current.Username {
		t.Fatalf("Name=%q want %q", u.Name, current.Username)
	}
	if len(u.Groups) == 0 {
		t.Fatal("expected at least one group")
	}
}

func TestLookupCurrentGroup(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("current user unavailable: %v", err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Skipf("current group unavailable: %v", err)
	}
	g, err := LookupGroup(group.Name)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := strconv.ParseUint(current.Gid, 10, 32)
	if g.GID != uint32(want) {
		t.Fatalf("GID=%d want %d", g.GID, want)
	}
}

func TestLookupUnknownShadow(t *testing.T) {
	if _, err := LookupShadow("gosshd-definitely-not-a-user"); err == nil {
		t.Fatal("expected lookup to fail")
	}
}

func TestLookupUserRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", "bad\x00name"} {
		if _, err := LookupUser(name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}
