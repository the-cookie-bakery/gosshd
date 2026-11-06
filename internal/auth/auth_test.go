package auth

import (
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
	if _, err := a.Password("someone", make([]byte, maxPasswordLength+1), nil); err != ErrInvalidLogin {
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
	perms, err := a.lookupAuthorizedKey(u, cert, remote)
	if err != nil {
		t.Fatal(err)
	}
	if perms == nil {
		t.Fatal("expected permissions")
	}

	cert.ValidPrincipals = []string{"other"}
	bad := *cert
	if _, err := a.lookupAuthorizedKey(u, &bad, remote); err == nil {
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
