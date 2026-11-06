package auth

import (
	"net"
	"testing"

	"github.com/cookiengineer/gosshd/internal/nss"
)

func TestSourceAllowed(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}
	for _, v := range []string{"192.0.2.10", "192.0.2.0/24", "192.0.2.*"} {
		if !sourceAllowed(v, addr) {
			t.Fatalf("%q should match", v)
		}
	}
	if sourceAllowed("198.51.100.0/24", addr) {
		t.Fatal("unexpected source match")
	}
}

func TestParseKeyOptions(t *testing.T) {
	p, err := parseKeyOptions([]string{`from="192.0.2.0/24"`, `command="echo ok"`, "no-pty", "restrict"}, nil, &net.TCPAddr{IP: net.ParseIP("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	if p.ForceCommand != "echo ok" || !p.NoPTY || p.SourceAddress == "" {
		t.Fatalf("unexpected permissions: %+v", p)
	}
}

func TestParseKeyOptionsRejectsUnknown(t *testing.T) {
	if _, err := parseKeyOptions([]string{"unknown-option"}, nil, nil); err == nil {
		t.Fatal("expected unknown option rejection")
	}
}

func TestExpandTokens(t *testing.T) {
	u := &nss.User{Name: "test", UID: 1000, Home: "/home/test"}
	out, err := expandTokens("%h/.ssh/%u-%U-%%", u)
	if err != nil {
		t.Fatal(err)
	}
	if out != "/home/test/.ssh/test-1000-%" {
		t.Fatalf("got %q", out)
	}
}

func TestMatchUserHost(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if !matchUserHost("ali*", "alice", addr) {
		t.Fatal("user wildcard did not match")
	}
	if !matchUserHost("alice@192.0.2.0/24", "alice", addr) {
		t.Fatal("host cidr did not match")
	}
	if matchUserHost("bob", "alice", addr) {
		t.Fatal("unexpected match")
	}
}
