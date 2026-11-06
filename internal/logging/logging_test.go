package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	for input, want := range map[string]Level{
		"DEBUG":   Debug,
		"debug2":  Debug,
		"INFO":    Info,
		"WARNING": Warning,
		"warn":    Warning,
		"ERROR":   Error,
		"unknown": Info,
	} {
		if got := ParseLevel(input); got != want {
			t.Fatalf("ParseLevel(%q)=%v want %v", input, got, want)
		}
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	Configure("WARNING", "AUTH", true)
	SetOutput(&buf)
	Infof("hidden message")
	Warningf("shown message")
	if strings.Contains(buf.String(), "hidden message") {
		t.Fatalf("info message was not filtered: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "shown message") {
		t.Fatalf("warning message missing: %s", buf.String())
	}
}
