package config

import (
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader(`
Port 2222
ListenAddress 127.0.0.1:2223
ListenAddress ::1
HostKey /tmp/host_ed25519
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u
AcceptEnv LANG LC_*
SetEnv FOO=bar
Subsystem sftp internal-sftp
KexAlgorithms curve25519-sha256
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 2222 {
		t.Fatalf("Port=%d", cfg.Port)
	}
	if len(cfg.ListenAddresses) != 2 {
		t.Fatalf("ListenAddresses=%v", cfg.ListenAddresses)
	}
	if cfg.ListenAddresses[0].Port != 2223 {
		t.Fatalf("listen port=%d", cfg.ListenAddresses[0].Port)
	}
	if cfg.PasswordAuthentication {
		t.Fatal("password auth should be disabled")
	}
	if len(cfg.AuthorizedKeysFile) != 2 {
		t.Fatalf("AuthorizedKeysFile=%v", cfg.AuthorizedKeysFile)
	}
	if cfg.SetEnv["FOO"] != "bar" {
		t.Fatalf("SetEnv=%v", cfg.SetEnv)
	}
	if cfg.Subsystems["sftp"] != "internal-sftp" {
		t.Fatalf("Subsystems=%v", cfg.Subsystems)
	}
}

func TestFirstValueWins(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("Port 2200\nPort 2201\nMaxAuthTries 3\nMaxAuthTries 9\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 2200 {
		t.Fatalf("Port=%d", cfg.Port)
	}
	if cfg.MaxAuthTries != 3 {
		t.Fatalf("MaxAuthTries=%d", cfg.MaxAuthTries)
	}
}

func TestQuotesAndComments(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader(`
# comment
Banner "/tmp/a banner"
ForceCommand "/bin/echo hello # not a comment"
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Banner != "/tmp/a banner" {
		t.Fatalf("Banner=%q", cfg.Banner)
	}
	if cfg.ForceCommand != "/bin/echo hello # not a comment" {
		t.Fatalf("ForceCommand=%q", cfg.ForceCommand)
	}
}

func TestUnknownKeyword(t *testing.T) {
	if _, err := ParseReader(strings.NewReader("DefinitelyNotAKeyword yes\n"), "test"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseOption(t *testing.T) {
	cfg := Default()
	if err := ParseOption(cfg, "PasswordAuthentication no"); err != nil {
		t.Fatal(err)
	}
	if cfg.PasswordAuthentication {
		t.Fatal("option not applied")
	}
}
