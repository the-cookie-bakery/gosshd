package nss

import (
	"os/user"
	"strconv"
	"testing"
	"time"
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

func TestParsePasswdLine(t *testing.T) {
	u, err := parsePasswdLine("alice:x:1000:1000:Alice:/home/alice:/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "alice" || u.UID != 1000 || u.GID != 1000 || u.Home != "/home/alice" || u.Shell != "/bin/sh" {
		t.Fatalf("unexpected user: %+v", u)
	}
}

func TestParseShadowLine(t *testing.T) {
	s, err := parseShadowLine("alice:$6$hash:19000:0:99999:7:14:20000:0")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "alice" || s.Hash != "$6$hash" || s.LastChange != 19000 || s.Max != 99999 || s.Inact != 14 || s.Expire != 20000 {
		t.Fatalf("unexpected shadow: %+v", s)
	}
}

func TestParseGroupLine(t *testing.T) {
	g, err := parseGroupLine("staff:x:50:alice,bob")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "staff" || g.GID != 50 {
		t.Fatalf("unexpected group: %+v", g)
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"alice", "systemd-network", "a_b"} {
		if !validName(name) {
			t.Fatalf("%q should be valid", name)
		}
	}
	for _, name := range []string{"", "-alice", "a:b", "a b", "a\nb", "bad\x00name"} {
		if validName(name) {
			t.Fatalf("%q should be invalid", name)
		}
	}
}

func TestCacheExpiry(t *testing.T) {
	c := newTTLCache[int](time.Minute, time.Millisecond)
	c.set("x", 1, true)
	if v, found, ok := c.get("x"); !ok || !found || v != 1 {
		t.Fatalf("unexpected cache result: %v %v %v", v, found, ok)
	}
	c.set("y", 0, false)
	time.Sleep(5 * time.Millisecond)
	if _, _, ok := c.get("y"); ok {
		t.Fatal("negative entry did not expire")
	}
}
