package privsep

import (
	"testing"
	"time"
)

func TestAuthLimiterDelay(t *testing.T) {
	l := newAuthLimiter()
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	const ip = "192.0.2.10"

	for i := 0; i < authLimitFailures; i++ {
		if d := l.delay(ip); d != 0 {
			t.Fatalf("unexpected delay after %d failures: %v", i, d)
		}
		l.failure(ip)
	}
	if d := l.delay(ip); d != authLimitExtraDelay {
		t.Fatalf("delay=%v want %v", d, authLimitExtraDelay)
	}
	now = now.Add(authLimitWindow)
	if d := l.delay(ip); d != 0 {
		t.Fatalf("delay after window=%v", d)
	}
	l.failure(ip)
	l.success(ip)
	if d := l.delay(ip); d != 0 {
		t.Fatalf("delay after success=%v", d)
	}
}

func TestRemoteHost(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:2222":   "192.0.2.1",
		"[2001:db8::1]:22": "2001:db8::1",
		"":                 "",
		"192.0.2.1":        "192.0.2.1",
	} {
		if got := remoteHost(in); got != want {
			t.Fatalf("remoteHost(%q)=%q want %q", in, got, want)
		}
	}
}
