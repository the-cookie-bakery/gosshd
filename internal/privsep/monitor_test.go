package privsep

import (
	"testing"

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
