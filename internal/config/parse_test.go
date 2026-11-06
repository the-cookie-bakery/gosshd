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

func TestAuthenticationMethods(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("AuthenticationMethods publickey,password publickey,keyboard-interactive\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuthenticationMethods) != 2 {
		t.Fatalf("alternatives=%v", cfg.AuthenticationMethods)
	}
	if got := strings.Join(cfg.AuthenticationMethods[0], ","); got != "publickey,password" {
		t.Fatalf("alternative 0=%q", got)
	}
	if got := strings.Join(cfg.AuthenticationMethods[1], ","); got != "publickey,keyboard-interactive" {
		t.Fatalf("alternative 1=%q", got)
	}
	if _, err := ParseReader(strings.NewReader("AuthenticationMethods publickey,bogus\n"), "test"); err == nil {
		t.Fatal("expected unsupported method to be rejected")
	}
	if _, err := ParseReader(strings.NewReader("AuthenticationMethods publickey,,password\n"), "test"); err == nil {
		t.Fatal("expected empty method to be rejected")
	}
}

func TestValidateAuthenticationMethodsToggles(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("PasswordAuthentication no\nAuthenticationMethods publickey,password\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected disabled password method to be rejected")
	}
	cfg, err = ParseReader(strings.NewReader("AuthenticationMethods publickey,password\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsNegativeLoginGraceTime(t *testing.T) {
	if _, err := ParseReader(strings.NewReader("LoginGraceTime -5\n"), "test"); err == nil {
		t.Fatal("expected negative LoginGraceTime to be rejected")
	}
}

func TestRequiredRSASize(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("RequiredRSASize 3072\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequiredRSASize != 3072 {
		t.Fatalf("RequiredRSASize=%d", cfg.RequiredRSASize)
	}
	if Default().RequiredRSASize != 2048 {
		t.Fatalf("default RequiredRSASize=%d", Default().RequiredRSASize)
	}
	if _, err := ParseReader(strings.NewReader("RequiredRSASize 512\n"), "test"); err == nil {
		t.Fatal("expected undersized RequiredRSASize to be rejected")
	}
}

func TestAcceptsZeroLoginGraceTime(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("LoginGraceTime 0\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoginGraceTime != 0 {
		t.Fatalf("LoginGraceTime=%v", cfg.LoginGraceTime)
	}
}

func TestAuthorizedCommandParsing(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("AuthorizedKeysCommand /bin/true %u\nAuthorizedKeysCommandUser root\nAuthorizedPrincipalsCommand /bin/true %s\nAuthorizedPrincipalsCommandUser root\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuthorizedKeysCommand) != 2 || cfg.AuthorizedKeysCommand[0] != "/bin/true" || cfg.AuthorizedKeysCommand[1] != "%u" {
		t.Fatalf("AuthorizedKeysCommand=%v", cfg.AuthorizedKeysCommand)
	}
	if len(cfg.AuthorizedPrincipalsCommand) != 2 || cfg.AuthorizedPrincipalsCommand[1] != "%s" {
		t.Fatalf("AuthorizedPrincipalsCommand=%v", cfg.AuthorizedPrincipalsCommand)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizedCommandRequiresUser(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("AuthorizedKeysCommand /bin/true\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected AuthorizedKeysCommand without user to be rejected")
	}
	cfg, err = ParseReader(strings.NewReader("AuthorizedPrincipalsCommand /bin/true\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected AuthorizedPrincipalsCommand without user to be rejected")
	}
}
