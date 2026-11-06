package privsep

import (
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

const (
	authFailureDelay    = 250 * time.Millisecond
	authFailureJitter   = 250 * time.Millisecond
	authLimitWindow     = time.Minute
	authLimitFailures   = 8
	authLimitExtraDelay = time.Second
)

type limiterEntry struct {
	failures int
	window   time.Time
}

type authLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*limiterEntry
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{now: time.Now, entries: map[string]*limiterEntry{}}
}

func (l *authLimiter) delay(key string) time.Duration {
	if key == "" {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil || l.now().Sub(e.window) >= authLimitWindow {
		return 0
	}
	if e.failures >= authLimitFailures {
		return authLimitExtraDelay
	}
	return 0
}

func (l *authLimiter) failure(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil || now.Sub(e.window) >= authLimitWindow {
		l.entries[key] = &limiterEntry{failures: 1, window: now}
		l.prune(now)
		return
	}
	e.failures++
}

func (l *authLimiter) success(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func (l *authLimiter) prune(now time.Time) {
	if len(l.entries) <= 1024 {
		return
	}
	for key, e := range l.entries {
		if now.Sub(e.window) >= authLimitWindow {
			delete(l.entries, key)
		}
	}
}

func authFailureSleep() {
	jitter := time.Duration(0)
	if authFailureJitter > 0 {
		jitter = time.Duration(rand.Int64N(int64(authFailureJitter)))
	}
	time.Sleep(authFailureDelay + jitter)
}

func remoteHost(remote string) string {
	if remote == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		return host
	}
	return remote
}
