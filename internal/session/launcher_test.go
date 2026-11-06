package session

import (
	"strings"
	"testing"
)

func TestEnsureEnvKeepsExisting(t *testing.T) {
	in := []string{"PATH=/bin", "HOME=/home/test"}
	out := ensureEnv(in)
	if len(out) != len(in) {
		t.Fatalf("unexpected env: %v", out)
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("env changed: %v", out)
		}
	}
}

func TestEnsureEnvAddsPath(t *testing.T) {
	out := ensureEnv([]string{"HOME=/home/test"})
	if !hasEnv(out, "PATH=") {
		t.Fatalf("PATH missing: %v", out)
	}
}

func TestMustGetwd(t *testing.T) {
	if got := mustGetwd(); got == "" {
		t.Fatal("empty working directory")
	}
}

func hasEnv(env []string, prefix string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}
