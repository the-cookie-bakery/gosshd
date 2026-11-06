package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/config"
)

func TestApplyDefaults(t *testing.T) {
	cfg := config.Default()
	if err := Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.KexAlgorithms) == 0 || len(cfg.Ciphers) == 0 || len(cfg.MACs) == 0 {
		t.Fatal("defaults not applied")
	}
	for _, v := range cfg.MACs {
		if v == ssh.HMACSHA1 {
			t.Fatal("hmac-sha1 must not be enabled")
		}
	}
}

func TestRejectWeakAlgorithms(t *testing.T) {
	for _, tc := range [][]string{
		{"diffie-hellman-group1-sha1"},
		{"diffie-hellman-group14-sha1"},
		{"3des-cbc"},
		{"aes128-cbc"},
		{"arcfour"},
		{"hmac-sha1"},
	} {
		cfg := config.Default()
		cfg.KexAlgorithms = []string{"curve25519-sha256"}
		cfg.Ciphers = []string{"aes256-ctr"}
		cfg.MACs = []string{"hmac-sha2-256"}
		switch tc[0] {
		case "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1":
			cfg.KexAlgorithms = tc
		case "3des-cbc", "aes128-cbc", "arcfour":
			cfg.Ciphers = tc
		case "hmac-sha1":
			cfg.MACs = tc
		}
		if err := Apply(cfg); err == nil {
			t.Fatalf("expected %q to be rejected", tc[0])
		}
	}
}

func TestLoadHostSigners(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "host")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signers, err := LoadHostSigners([]string{path}, nil, []string{ssh.KeyAlgoED25519}, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 || signers[0].PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("unexpected signers: %v", signers)
	}
	if _, err := LoadHostSigners([]string{path}, nil, []string{ssh.KeyAlgoRSA}, 2048); err == nil {
		t.Fatal("expected disallowed host key to fail")
	}
}

func TestLoadHostSignersRSAMinimum(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "host_rsa")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := []string{ssh.KeyAlgoRSASHA256}
	if _, err := LoadHostSigners([]string{path}, nil, allowed, 2048); err == nil {
		t.Fatal("expected 1024-bit RSA host key to be rejected")
	}
	if _, err := LoadHostSigners([]string{path}, nil, allowed, 1024); err != nil {
		t.Fatalf("expected 1024-bit RSA host key to be accepted: %v", err)
	}
}

func TestCASignatureAlgorithmDefaultsAndValidation(t *testing.T) {
	cfg := config.Default()
	if err := Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.CASignatureAlgorithms) == 0 {
		t.Fatal("default CASignatureAlgorithms not applied")
	}
	cfg.CASignatureAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA512}
	if err := Apply(cfg); err != nil {
		t.Fatalf("valid algorithms rejected: %v", err)
	}
	for _, algorithm := range []string{ssh.KeyAlgoRSA, "ssh-dss", ssh.KeyAlgoED25519 + "-cert-v01@openssh.com", "bogus"} {
		cfg := config.Default()
		cfg.CASignatureAlgorithms = []string{algorithm}
		if err := Apply(cfg); err == nil {
			t.Fatalf("expected %q to be rejected", algorithm)
		}
	}
}
