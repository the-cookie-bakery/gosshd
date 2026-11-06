package privsep

import (
	"testing"
	"time"

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
	cfg := config.Default()
	cfg.PasswordAuthentication = false
	cfg.KbdInteractiveAuthentication = false
	m := &Monitor{cfg: cfg, limiter: newAuthLimiter()}
	st := newSessionState()
	for _, pkt := range []*Packet{
		{Type: "password", User: "alice"},
		{Type: "keyboard", User: "alice"},
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
