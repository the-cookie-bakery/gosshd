package privsep

import (
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKeepaliveState(t *testing.T) {
	k := newKeepaliveState(3)
	if send, closeConn := k.tick(); !send || closeConn {
		t.Fatalf("first tick: send=%v close=%v", send, closeConn)
	}
	if send, closeConn := k.tick(); send || closeConn {
		t.Fatalf("missing reply should wait: send=%v close=%v", send, closeConn)
	}
	k.reply()
	if send, closeConn := k.tick(); !send || closeConn {
		t.Fatalf("tick after reply: send=%v close=%v", send, closeConn)
	}
	if send, closeConn := k.tick(); send || closeConn {
		t.Fatalf("failure 1: send=%v close=%v", send, closeConn)
	}
	if send, closeConn := k.tick(); send || closeConn {
		t.Fatalf("failure 2: send=%v close=%v", send, closeConn)
	}
	if send, closeConn := k.tick(); send || !closeConn {
		t.Fatalf("failure 3: send=%v close=%v", send, closeConn)
	}
}

func TestHandleGlobalRequests(t *testing.T) {
	reqs := make(chan *ssh.Request, 3)
	var noMore atomic.Bool
	done := make(chan struct{})
	go func() {
		handleGlobalRequests(reqs, &noMore)
		close(done)
	}()
	reqs <- &ssh.Request{Type: "keepalive@openssh.com"}
	reqs <- &ssh.Request{Type: "unknown-request"}
	reqs <- &ssh.Request{Type: "no-more-sessions@openssh.com"}
	close(reqs)
	<-done
	if !noMore.Load() {
		t.Fatal("no-more-sessions flag not set")
	}
}
