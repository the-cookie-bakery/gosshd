package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/config"
	"github.com/cookiengineer/gosshd/internal/nss"
)

func TestSourceAllowed(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}
	for _, v := range []string{"192.0.2.10", "192.0.2.0/24", "192.0.2.*"} {
		if !sourceAllowed(v, addr) {
			t.Fatalf("%q should match", v)
		}
	}
	if sourceAllowed("198.51.100.0/24", addr) {
		t.Fatal("unexpected source match")
	}
}

func TestParseKeyOptions(t *testing.T) {
	p, err := parseKeyOptions([]string{`from="192.0.2.0/24"`, `command="echo ok"`, "no-pty", "restrict"}, nil, &net.TCPAddr{IP: net.ParseIP("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	if p.ForceCommand != "echo ok" || !p.NoPTY || p.SourceAddress == "" {
		t.Fatalf("unexpected permissions: %+v", p)
	}
}

func TestParseKeyOptionsRejectsUnknown(t *testing.T) {
	if _, err := parseKeyOptions([]string{"unknown-option"}, nil, nil); err == nil {
		t.Fatal("expected unknown option rejection")
	}
}

func TestExpandTokens(t *testing.T) {
	u := &nss.User{Name: "test", UID: 1000, Home: "/home/test"}
	out, err := expandTokens("%h/.ssh/%u-%U-%%", u)
	if err != nil {
		t.Fatal(err)
	}
	if out != "/home/test/.ssh/test-1000-%" {
		t.Fatalf("got %q", out)
	}
}

func TestMatchUserHost(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if !matchUserHost("ali*", "alice", addr) {
		t.Fatal("user wildcard did not match")
	}
	if !matchUserHost("alice@192.0.2.0/24", "alice", addr) {
		t.Fatal("host cidr did not match")
	}
	if matchUserHost("bob", "alice", addr) {
		t.Fatal("unexpected match")
	}
}

func TestPasswordLengthLimit(t *testing.T) {
	a, err := New(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Password("password", "someone", make([]byte, maxPasswordLength+1), nil, nil); err != ErrInvalidLogin {
		t.Fatalf("got %v, want ErrInvalidLogin", err)
	}
}

func TestCheckRSASize(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	large, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	smallPub, err := ssh.NewPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	largePub, err := ssh.NewPublicKey(&large.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRSASize(smallPub, 2048); err == nil {
		t.Fatal("expected small RSA key to be rejected")
	}
	if err := checkRSASize(largePub, 2048); err != nil {
		t.Fatal(err)
	}
	if err := checkRSASize(largePub, 1024); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizedKeysCertAuthority(t *testing.T) {
	dir := t.TempDir()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	sshCAPub, err := ssh.NewPublicKey(caPub)
	if err != nil {
		t.Fatal(err)
	}
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshUserPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:             sshUserPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "authorized_keys")
	line := append([]byte(`cert-authority,principals="test" `), ssh.MarshalAuthorizedKey(sshCAPub)...)
	if err := os.WriteFile(path, line, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.AuthorizedKeysFile = []string{path}
	cfg.StrictModes = false
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	u := &nss.User{Name: "test", Home: dir}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}
	perms, err := a.lookupAuthorizedKey(cfg, u, cert, remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	if perms == nil {
		t.Fatal("expected permissions")
	}

	cert.ValidPrincipals = []string{"other"}
	bad := *cert
	if _, err := a.lookupAuthorizedKey(cfg, u, &bad, remote, nil); err == nil {
		t.Fatal("expected mismatched principal to be rejected")
	}
}

func TestDummyPasswordHashIsValid(t *testing.T) {
	a, err := New(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.decoder.Decode(dummyPasswordHash); err != nil {
		t.Fatalf("dummy hash does not decode: %v", err)
	}
}

func TestExpandCommandArg(t *testing.T) {
	ctx := tokenContext{
		username:      "alice",
		uid:           "1000",
		home:          "/home/alice",
		keyType:       "ssh-ed25519",
		keyBlob:       "blob",
		fingerprint:   "SHA256:key",
		connection:    "192.0.2.1 1234 192.0.2.2 22",
		keyID:         "id",
		serial:        "42",
		caType:        "ssh-ed25519",
		caBlob:        "cab",
		caFingerprint: "SHA256:ca",
	}
	for in, want := range map[string]string{
		"%u":   "alice",
		"%U":   "1000",
		"%h":   "/home/alice",
		"%t":   "ssh-ed25519",
		"%k":   "blob",
		"%f":   "SHA256:key",
		"%C":   "192.0.2.1 1234 192.0.2.2 22",
		"%%":   "%",
		"x%uy": "xalicey",
	} {
		got, err := expandCommandArg(in, ctx, false)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q=%q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"%F": "SHA256:ca",
		"%i": "id",
		"%K": "cab",
		"%s": "42",
		"%T": "ssh-ed25519",
	} {
		got, err := expandCommandArg(in, ctx, true)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q=%q want %q", in, got, want)
		}
	}
	if _, err := expandCommandArg("%i", ctx, false); err == nil {
		t.Fatal("expected cert token to be rejected for keys command")
	}
	if _, err := expandCommandArg("%z", ctx, true); err == nil {
		t.Fatal("expected unknown token to be rejected")
	}
}

func TestCommandSpecValidation(t *testing.T) {
	if _, err := newCommandSpec([]string{"/bin/true"}, ""); err == nil {
		t.Fatal("expected missing command user to be rejected")
	}
	if _, err := newCommandSpec([]string{"true"}, "root"); err == nil {
		t.Fatal("expected relative command path to be rejected")
	}
	if _, err := newCommandSpec([]string{"/definitely/not/here"}, "root"); err == nil {
		t.Fatal("expected missing command to be rejected")
	}
}

func TestScanAuthorizedKeysReader(t *testing.T) {
	u := &nss.User{Name: "alice", Home: "/home/alice"}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line := append([]byte(`command="echo hello" `), ssh.MarshalAuthorizedKey(signer.PublicKey())...)
	p, found, err := scanAuthorizedKeys(bytes.NewReader(line), signer.PublicKey(), u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !found || p.ForceCommand != "echo hello" {
		t.Fatalf("found=%v perms=%+v", found, p)
	}
}

func TestReadPrincipalsReader(t *testing.T) {
	principals, err := readPrincipals(bytes.NewReader([]byte("# comment\nalice\nbob extra\n\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(principals) != 2 || principals[0] != "alice" || principals[1] != "bob" {
		t.Fatalf("principals=%v", principals)
	}
	if _, err := readPrincipals(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected empty principals to fail")
	}
}
