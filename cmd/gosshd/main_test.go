package main

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cookiengineer/gosshd/internal/config"
)

func TestSystemdListenersInactive(t *testing.T) {
	t.Setenv("LISTEN_PID", "")
	t.Setenv("LISTEN_FDS", "")
	listeners, activated, err := systemdListeners()
	if err != nil {
		t.Fatal(err)
	}
	if activated || len(listeners) != 0 {
		t.Fatalf("activated=%v listeners=%d", activated, len(listeners))
	}
}

func TestSystemdListenersInvalidEnvironment(t *testing.T) {
	t.Setenv("LISTEN_PID", "1")
	t.Setenv("LISTEN_FDS", "1")
	if listeners, activated, err := systemdListeners(); err != nil || activated || len(listeners) != 0 {
		t.Fatalf("mismatched pid: activated=%v listeners=%d err=%v", activated, len(listeners), err)
	}

	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "0")
	if listeners, activated, err := systemdListeners(); err != nil || activated || len(listeners) != 0 {
		t.Fatalf("zero fds: activated=%v listeners=%d err=%v", activated, len(listeners), err)
	}

	t.Setenv("LISTEN_FDS", "1")
	if listeners, activated, err := systemdListeners(); err == nil || !activated || len(listeners) != 0 {
		t.Fatalf("invalid fd: activated=%v listeners=%d err=%v", activated, len(listeners), err)
	}
}

func TestReloadCompatible(t *testing.T) {
	old := config.Default()
	old.Port = 2222
	next := old.Clone()
	if err := reloadCompatible(old, next); err != nil {
		t.Fatalf("identical configs rejected: %v", err)
	}
	next.Port = 2223
	if err := reloadCompatible(old, next); err == nil {
		t.Fatal("Port change was accepted")
	}
	next = old.Clone()
	next.HostKeys = []string{"/etc/ssh/other"}
	if err := reloadCompatible(old, next); err == nil {
		t.Fatal("HostKey change was accepted")
	}
	next = old.Clone()
	next.MaxStartupsRate = 99
	if err := reloadCompatible(old, next); err == nil {
		t.Fatal("MaxStartupsRate change was accepted")
	}
	next = old.Clone()
	next.MaxStartupsFull = 200
	if err := reloadCompatible(old, next); err == nil {
		t.Fatal("MaxStartupsFull change was accepted")
	}
}

func TestParseGrace(t *testing.T) {
	if d, err := parseGrace("2m"); err != nil || d != 2*time.Minute {
		t.Fatalf("d=%v err=%v", d, err)
	}
	if d, err := parseGrace("90"); err != nil || d != 90*time.Second {
		t.Fatalf("d=%v err=%v", d, err)
	}
}
