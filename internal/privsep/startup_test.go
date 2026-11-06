package privsep

import (
	"sync"
	"testing"

	"github.com/cookiengineer/gosshd/internal/config"
)

func startupConfig(start, rate, full int) *config.Config {
	cfg := config.Default()
	cfg.MaxStartups = start
	cfg.MaxStartupsRate = rate
	cfg.MaxStartupsFull = full
	return cfg
}

func TestAcceptStartupBoundaries(t *testing.T) {
	m := &Monitor{cfg: startupConfig(2, 0, 3), randIntN: func(int) int { return 99 }}
	for i := 0; i < 3; i++ {
		if !m.acceptStartup() {
			t.Fatalf("connection %d should be accepted", i)
		}
	}
	if m.acceptStartup() {
		t.Fatal("connection at full threshold should be rejected")
	}
	m.releaseStartup()
	if !m.acceptStartup() {
		t.Fatal("released slot should be reusable")
	}
}

func TestAcceptStartupRandomDrop(t *testing.T) {
	m := &Monitor{cfg: startupConfig(1, 100, 5), randIntN: func(int) int { return 0 }}
	if !m.acceptStartup() {
		t.Fatal("first connection should be accepted")
	}
	if m.acceptStartup() {
		t.Fatal("connection at start threshold should be dropped at rate 100")
	}
	m = &Monitor{cfg: startupConfig(1, 0, 5), randIntN: func(int) int { return 0 }}
	if !m.acceptStartup() {
		t.Fatal("first connection should be accepted")
	}
	if !m.acceptStartup() {
		t.Fatal("connection should be accepted when rate is zero before full")
	}
}

func TestMarkAuthenticatedReleasesOnce(t *testing.T) {
	calls := 0
	st := newSessionState()
	st.releaseStartup = sync.OnceFunc(func() { calls++ })
	st.markAuthenticated()
	st.markAuthenticated()
	if calls != 1 {
		t.Fatalf("release called %d times, want 1", calls)
	}
}
