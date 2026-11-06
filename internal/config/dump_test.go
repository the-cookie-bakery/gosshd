package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteEffective(t *testing.T) {
	cfg := Default()
	cfg.Port = 2222
	cfg.ListenAddresses = []ListenAddress{{Host: "127.0.0.1", Port: 2223}}
	cfg.Subsystems = map[string]string{"sftp": "internal-sftp"}
	cfg.SetEnv = map[string]string{"B": "2", "A": "1"}
	var buf bytes.Buffer
	if err := cfg.WriteEffective(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"port 2222\n",
		"listenaddress 127.0.0.1:2223\n",
		"maxstartups 10:30:100\n",
		"usedns no\n",
		"compression no\n",
		"setenv A=1\nsetenv B=2\n",
		"subsystem sftp internal-sftp\n",
		"requiredrsasize 2048\n",
		"usepam no\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}
