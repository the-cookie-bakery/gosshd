package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	h := New(t, Options{})
	if h.opts.Runtime != "podman" {
		t.Fatalf("Runtime=%q", h.opts.Runtime)
	}
	if h.opts.Arch == "" {
		t.Fatal("Arch is empty")
	}
	if h.opts.Timeout != 10*time.Minute {
		t.Fatalf("Timeout=%v", h.opts.Timeout)
	}
	if h.opts.ArtifactsDir == "" {
		t.Fatal("ArtifactsDir is empty")
	}
	if h.name == "" {
		t.Fatal("name is empty")
	}
}

func TestRandomSuffix(t *testing.T) {
	a := randomSuffix()
	b := randomSuffix()
	if len(a) != 8 || len(b) != 8 {
		t.Fatalf("suffix lengths: %d %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("random suffixes collided")
	}
}

func TestResolveArtifactsDir(t *testing.T) {
	t.Setenv("GOSSHD_E2E_ARTIFACTS", "")
	now := time.Date(2026, 11, 6, 12, 34, 56, 0, time.UTC)
	if got := ResolveArtifactsDir("/repo", false, now); got != "" {
		t.Fatalf("non-keep dir=%q", got)
	}
	got := ResolveArtifactsDir("/repo", true, now)
	if !strings.Contains(got, filepath.Join("e2e-tests", ".artifacts")) || !strings.HasSuffix(got, "20261106-123456") {
		t.Fatalf("keep dir=%q", got)
	}
	t.Setenv("GOSSHD_E2E_ARTIFACTS", "/custom")
	if got := ResolveArtifactsDir("/repo", true, now); got != "/custom" {
		t.Fatalf("override dir=%q", got)
	}
}

func TestCloseRemovesContainer(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	script := filepath.Join(dir, "runtime")
	body := `#!/bin/sh
printf '%s\n' "$*" >> "$LOG"
if [ "$1" = "container" ]; then
	exit 1
fi
exit 0
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOG", logPath)
	h := New(t, Options{Runtime: script})
	h.name = "gosshd-e2e-test"
	h.started = true
	h.Close()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	if !strings.Contains(log, "rm -f gosshd-e2e-test") {
		t.Fatalf("remove was not attempted: %s", log)
	}
	if !strings.Contains(log, "container exists gosshd-e2e-test") {
		t.Fatalf("leak check was not attempted: %s", log)
	}
}
