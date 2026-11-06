package harness

import (
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
