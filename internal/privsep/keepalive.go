package privsep

import (
	"time"

	"golang.org/x/crypto/ssh"
)

type keepaliveState struct {
	max      int
	pending  bool
	failures int
}

func newKeepaliveState(max int) *keepaliveState {
	return &keepaliveState{max: max}
}

func (k *keepaliveState) tick() (send bool, closeConn bool) {
	if k.pending {
		k.failures++
		if k.failures >= k.max {
			return false, true
		}
		return false, false
	}
	k.pending = true
	k.failures = 0
	return true, false
}

func (k *keepaliveState) reply() {
	k.pending = false
	k.failures = 0
}

func startClientAlive(conn ssh.Conn, interval time.Duration, countMax int, stop <-chan struct{}) {
	if interval <= 0 || countMax <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		state := newKeepaliveState(countMax)
		replies := make(chan struct{}, 1)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				send, closeConn := state.tick()
				if closeConn {
					_ = conn.Close()
					return
				}
				if send {
					go func() {
						_, _, _ = conn.SendRequest("keepalive@openssh.com", true, nil)
						select {
						case replies <- struct{}{}:
						default:
						}
					}()
				}
			case <-replies:
				state.reply()
			}
		}
	}()
}
