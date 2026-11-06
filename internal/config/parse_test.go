package config

import (
	"net"
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

func TestMatchParsingAndResolution(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader(`
PasswordAuthentication yes
Match User alice,bob Group staff Address 192.0.2.0/24 LocalPort 22
    ForceCommand "echo matched"
    PermitTTY no
Match All
    MaxSessions 3
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Matches) != 2 {
		t.Fatalf("matches=%d", len(cfg.Matches))
	}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.5"), Port: 1234}
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	resolved := cfg.Resolve("alice", []string{"staff"}, remote, local)
	if resolved.ForceCommand != "echo matched" {
		t.Fatalf("ForceCommand=%q", resolved.ForceCommand)
	}
	if resolved.PermitTTY {
		t.Fatal("PermitTTY should be disabled by Match")
	}
	if resolved.MaxSessions != 3 {
		t.Fatalf("MaxSessions=%d", resolved.MaxSessions)
	}
	other := cfg.Resolve("carol", []string{"other"}, remote, local)
	if other.ForceCommand != "" {
		t.Fatalf("unexpected ForceCommand=%q", other.ForceCommand)
	}
	if other.MaxSessions != 3 {
		t.Fatalf("Match All MaxSessions=%d", other.MaxSessions)
	}
}

func TestMatchGlobalPrecedence(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader(`
ForceCommand "global"
Match User alice
    ForceCommand "matched"
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	resolved := cfg.Resolve("alice", nil, nil, nil)
	if resolved.ForceCommand != "global" {
		t.Fatalf("ForceCommand=%q", resolved.ForceCommand)
	}
}

func TestMatchFirstValueWithinBlock(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader(`
Match User alice
    ForceCommand "first"
    ForceCommand "second"
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	resolved := cfg.Resolve("alice", nil, nil, nil)
	if resolved.ForceCommand != "first" {
		t.Fatalf("ForceCommand=%q", resolved.ForceCommand)
	}
}

func TestMatchRejectsUnsupportedDirective(t *testing.T) {
	if _, err := ParseReader(strings.NewReader("Match User alice\nPort 2222\n"), "test"); err == nil {
		t.Fatal("expected unsupported Match directive to be rejected")
	}
}

func TestMatchRejectsInvalidCriteria(t *testing.T) {
	for _, input := range []string{
		"Match\n",
		"Match alice\n",
		"Match All User alice\n",
		"Match LocalPort nope\n",
	} {
		if _, err := ParseReader(strings.NewReader(input), "test"); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
}

func TestMatchAddressNegation(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("Match User alice Address *,!192.0.2.0/24\n    PermitTTY no\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if resolved := cfg.Resolve("alice", nil, &net.TCPAddr{IP: net.ParseIP("198.51.100.2")}, local); resolved.PermitTTY {
		t.Fatal("address negated pattern did not match")
	}
	if resolved := cfg.Resolve("alice", nil, &net.TCPAddr{IP: net.ParseIP("192.0.2.5")}, local); !resolved.PermitTTY {
		t.Fatal("negated address should be excluded")
	}
}

func TestMaxStartupsParsing(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("MaxStartups 10:30:100\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxStartups != 10 || cfg.MaxStartupsRate != 30 || cfg.MaxStartupsFull != 100 {
		t.Fatalf("MaxStartups=%d:%d:%d", cfg.MaxStartups, cfg.MaxStartupsRate, cfg.MaxStartupsFull)
	}

	cfg, err = ParseReader(strings.NewReader("MaxStartups 5\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxStartups != 5 || cfg.MaxStartupsRate != DefaultMaxStartupsRate || cfg.MaxStartupsFull != DefaultMaxStartupsFull {
		t.Fatalf("MaxStartups defaults=%d:%d:%d", cfg.MaxStartups, cfg.MaxStartupsRate, cfg.MaxStartupsFull)
	}

	for _, input := range []string{
		"MaxStartups -1\n",
		"MaxStartups 5:101:100\n",
		"MaxStartups 20:30:10\n",
		"MaxStartups 1:2:3:4\n",
		"MaxStartups nope\n",
	} {
		if _, err := ParseReader(strings.NewReader(input), "test"); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
}

func TestUseDNSAndCompressionTruthfulness(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("UseDNS no\nCompression no\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UseDNS {
		t.Fatal("UseDNS should be false")
	}
	if cfg.Compression != "no" {
		t.Fatalf("Compression=%q", cfg.Compression)
	}
	if _, err := ParseReader(strings.NewReader("UseDNS yes\n"), "test"); err == nil {
		t.Fatal("expected UseDNS yes to be rejected")
	}
	for _, input := range []string{"Compression yes\n", "Compression delayed\n", "Compression maybe\n"} {
		if _, err := ParseReader(strings.NewReader(input), "test"); err == nil {
			t.Fatalf("expected %q to be rejected", strings.TrimSpace(input))
		}
	}
}

func TestCASignatureAlgorithmsParsing(t *testing.T) {
	cfg, err := ParseReader(strings.NewReader("CASignatureAlgorithms ssh-ed25519,rsa-sha2-512\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.CASignatureAlgorithms, ","); got != "ssh-ed25519,rsa-sha2-512" {
		t.Fatalf("CASignatureAlgorithms=%q", got)
	}
}

func TestMatchRejectsGlobalOnlyTruthfulnessDirectives(t *testing.T) {
	for _, name := range []string{"Banner", "UseDNS", "Compression", "CASignatureAlgorithms"} {
		input := "Match User alice\n    " + name + " value\n"
		if _, err := ParseReader(strings.NewReader(input), "test"); err == nil {
			t.Fatalf("expected %s inside Match to be rejected", name)
		}
	}
}
