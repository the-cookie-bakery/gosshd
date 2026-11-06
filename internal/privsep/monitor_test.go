package privsep

import (
	"net"
	"os/user"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cookiengineer/gosshd/internal/auth"
	"github.com/cookiengineer/gosshd/internal/config"
)

func TestForgedSessionRequestsRejected(t *testing.T) {
	m := &Monitor{cfg: config.Default(), limiter: newAuthLimiter()}
	st := newSessionState()
	for _, pkt := range []*Packet{
		{Type: "session_open"},
		{Type: "session_resize", SessionID: "forged"},
		{Type: "session_signal", SessionID: "forged", Signal: 15},
		{Type: "session_wait", SessionID: "forged"},
	} {
		res := m.handlePacket(st, pkt)
		if res == nil || res.OK {
			t.Fatalf("%s: expected rejection, got %+v", pkt.Type, res)
		}
	}
}

func TestDisabledAuthMethodsRejected(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("current user unavailable: %v", err)
	}
	cfg := config.Default()
	cfg.PasswordAuthentication = false
	cfg.KbdInteractiveAuthentication = false
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := &Monitor{cfg: cfg, auth: a, limiter: newAuthLimiter()}
	st := newSessionState()
	for _, pkt := range []*Packet{
		{Type: "password", User: current.Username},
		{Type: "keyboard", User: current.Username},
	} {
		res := m.handlePacket(st, pkt)
		if res == nil || res.OK {
			t.Fatalf("%s: expected rejection, got %+v", pkt.Type, res)
		}
	}
}

func TestServeControlRejectsForgedRequests(t *testing.T) {
	a, b := newTestPacketConns(t)
	m := &Monitor{cfg: config.Default(), limiter: newAuthLimiter()}
	st := newSessionState()
	done := make(chan struct{})
	go func() {
		m.serveControl(a, st)
		close(done)
	}()

	for i, pkt := range []*Packet{
		{Type: "session_open"},
		{Type: "session_resize", SessionID: "forged"},
		{Type: "session_signal", SessionID: "forged", Signal: 15},
		{Type: "session_wait", SessionID: "forged"},
	} {
		pkt.ID = uint64(i + 1)
		if err := b.Write(pkt); err != nil {
			t.Fatal(err)
		}
		resp, _, err := b.Read()
		if err != nil {
			t.Fatal(err)
		}
		if resp.ID != pkt.ID || resp.Result == nil || resp.Result.OK {
			t.Fatalf("%s: got %+v", pkt.Type, resp)
		}
	}

	b.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveControl did not stop")
	}
}

func TestServeControlMalformedPacket(t *testing.T) {
	a, b := newTestPacketConns(t)
	m := &Monitor{cfg: config.Default(), limiter: newAuthLimiter()}
	st := newSessionState()
	done := make(chan struct{})
	go func() {
		m.serveControl(a, st)
		close(done)
	}()

	if _, _, err := b.conn.WriteMsgUnix([]byte("not-gob"), nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveControl did not stop after malformed packet")
	}
}

func TestSessionStateIsolation(t *testing.T) {
	st1 := newSessionState()
	st2 := newSessionState()
	if err := st1.addSessionIfRoom(&session{id: "shared"}, 10); err != nil {
		t.Fatal(err)
	}
	if st2.getSession("shared") != nil {
		t.Fatal("session leaked between connection states")
	}
}

func TestBuildEnv(t *testing.T) {
	cfg := config.Default()
	cfg.AcceptEnv = []string{"LANG"}
	cfg.SetEnv = map[string]string{"FOO": "bar"}
	cfg.PermitUserEnvironment = "yes"
	m := &Monitor{cfg: cfg}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	env := m.buildEnv(cfg, []string{"LANG=en_US.UTF-8", "TERM=xterm", "SECRET=x"}, &auth.Permissions{
		Username:    "alice",
		Home:        "/home/alice",
		Shell:       "/bin/sh",
		Environment: []string{"USERENV=1"},
	}, remote, local)
	for _, want := range []string{"LANG=en_US.UTF-8", "TERM=xterm", "FOO=bar", "USERENV=1", "SSH_CONNECTION=192.0.2.10 1234 192.0.2.1 22", "SSH_CLIENT=192.0.2.10 1234 22"} {
		found := false
		for _, kv := range env {
			if kv == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q in %v", want, env)
		}
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "SECRET=") {
			t.Fatalf("unexpected env %q", kv)
		}
	}
}

func TestSignalNumber(t *testing.T) {
	cases := map[string]syscall.Signal{
		"HUP":  syscall.SIGHUP,
		"INT":  syscall.SIGINT,
		"TERM": syscall.SIGTERM,
		"KILL": syscall.SIGKILL,
		"USR1": syscall.SIGUSR1,
	}
	for name, want := range cases {
		if got := signalNumber(name); got != want {
			t.Fatalf("signalNumber(%q)=%v want %v", name, got, want)
		}
	}
	if got := signalNumber("UNKNOWN"); got != syscall.SIGTERM {
		t.Fatalf("unknown signal=%v", got)
	}
}
