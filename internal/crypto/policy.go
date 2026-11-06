package crypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/config"
)

var (
	DefaultKeyExchanges = []string{
		ssh.KeyExchangeMLKEM768X25519,
		ssh.KeyExchangeCurve25519,
		ssh.KeyExchangeECDHP256,
		ssh.KeyExchangeECDHP384,
		ssh.KeyExchangeECDHP521,
		ssh.KeyExchangeDH16SHA512,
		ssh.KeyExchangeDH14SHA256,
	}
	DefaultCiphers = []string{
		ssh.CipherChaCha20Poly1305,
		ssh.CipherAES256GCM,
		ssh.CipherAES128GCM,
		ssh.CipherAES256CTR,
		ssh.CipherAES192CTR,
		ssh.CipherAES128CTR,
	}
	DefaultMACs = []string{
		ssh.HMACSHA512ETM,
		ssh.HMACSHA256ETM,
		ssh.HMACSHA512,
		ssh.HMACSHA256,
	}
	DefaultHostKeyAlgorithms = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
	}
	DefaultPubKeyAuthAlgorithms = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
	}
	DefaultCASignatureAlgorithms = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
	}
)

var signingAlgorithms = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoRSASHA512:  true,
	ssh.KeyAlgoRSASHA256:  true,
}

var insecure = map[string]bool{
	ssh.InsecureKeyExchangeDH1SHA1:   true,
	ssh.InsecureKeyExchangeDH14SHA1:  true,
	ssh.InsecureKeyExchangeDHGEXSHA1: true,
	ssh.InsecureCipherAES128CBC:      true,
	ssh.InsecureCipherTripleDESCBC:   true,
	ssh.InsecureCipherRC4:            true,
	ssh.InsecureCipherRC4128:         true,
	ssh.InsecureCipherRC4256:         true,
	ssh.InsecureHMACSHA196:           true,
	ssh.HMACSHA1:                     true,
	ssh.KeyAlgoRSA:                   true,
	"ssh-dss":                        true,
	ssh.CertAlgoRSAv01:               true,
	"ssh-dss-cert-v01@openssh.com":   true,
}

var knownModern = func() map[string]bool {
	m := map[string]bool{}
	for _, v := range DefaultKeyExchanges {
		m[v] = true
	}
	for _, v := range DefaultCiphers {
		m[v] = true
	}
	for _, v := range DefaultMACs {
		m[v] = true
	}
	for _, v := range DefaultHostKeyAlgorithms {
		m[v] = true
	}
	for _, v := range DefaultPubKeyAuthAlgorithms {
		m[v] = true
	}
	for _, v := range []string{
		ssh.KeyExchangeMLKEM768X25519,
		ssh.KeyExchangeDHGEXSHA256,
		ssh.CertAlgoRSASHA256v01,
		ssh.CertAlgoRSASHA512v01,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoED25519v01,
	} {
		m[v] = true
	}
	return m
}()

func Apply(cfg *config.Config) error {
	if len(cfg.KexAlgorithms) == 0 {
		cfg.KexAlgorithms = append([]string(nil), DefaultKeyExchanges...)
	} else if err := check(cfg.KexAlgorithms, "KexAlgorithms"); err != nil {
		return err
	}
	if len(cfg.Ciphers) == 0 {
		cfg.Ciphers = append([]string(nil), DefaultCiphers...)
	} else if err := check(cfg.Ciphers, "Ciphers"); err != nil {
		return err
	}
	if len(cfg.MACs) == 0 {
		cfg.MACs = append([]string(nil), DefaultMACs...)
	} else if err := check(cfg.MACs, "MACs"); err != nil {
		return err
	}
	if len(cfg.HostKeyAlgorithms) == 0 {
		cfg.HostKeyAlgorithms = append([]string(nil), DefaultHostKeyAlgorithms...)
	} else if err := check(cfg.HostKeyAlgorithms, "HostKeyAlgorithms"); err != nil {
		return err
	}
	if len(cfg.PubkeyAcceptedAlgorithms) == 0 {
		cfg.PubkeyAcceptedAlgorithms = append([]string(nil), DefaultPubKeyAuthAlgorithms...)
	} else if err := check(cfg.PubkeyAcceptedAlgorithms, "PubkeyAcceptedAlgorithms"); err != nil {
		return err
	}
	if len(cfg.CASignatureAlgorithms) == 0 {
		cfg.CASignatureAlgorithms = append([]string(nil), DefaultCASignatureAlgorithms...)
	} else if err := checkSigningAlgorithms(cfg.CASignatureAlgorithms, "CASignatureAlgorithms"); err != nil {
		return err
	}
	if cfg.RequiredRSASize == 0 {
		cfg.RequiredRSASize = 2048
	}
	if cfg.RequiredRSASize < 1024 {
		return fmt.Errorf("RequiredRSASize must be at least 1024")
	}
	return nil
}

func check(values []string, name string) error {
	for _, v := range values {
		if insecure[v] {
			return fmt.Errorf("%s contains unsupported insecure algorithm %q", name, v)
		}
		if !knownModern[v] {
			return fmt.Errorf("%s contains unsupported algorithm %q", name, v)
		}
	}
	return nil
}

func checkSigningAlgorithms(values []string, name string) error {
	for _, v := range values {
		if insecure[v] {
			return fmt.Errorf("%s contains unsupported insecure algorithm %q", name, v)
		}
		if !signingAlgorithms[v] {
			return fmt.Errorf("%s contains unsupported signing algorithm %q", name, v)
		}
	}
	return nil
}

func LoadHostSigners(paths []string, certPaths []string, allowed []string, requiredRSASize int) ([]ssh.Signer, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no host keys configured")
	}
	allowedSet := map[string]bool{}
	for _, a := range allowed {
		allowedSet[a] = true
	}
	signers := make([]ssh.Signer, 0, len(paths))
	byKey := map[string]ssh.Signer{}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat host key %s: %w", path, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("host key %s is group or world accessible", path)
		}
		if os.Geteuid() == 0 {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
				return nil, fmt.Errorf("host key %s is not owned by root", path)
			}
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read host key %s: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, err)
		}
		if err := checkRSASize(signer.PublicKey(), requiredRSASize); err != nil {
			return nil, fmt.Errorf("host key %s: %w", path, err)
		}
		signer, err = restrictSigner(signer, allowedSet)
		if err != nil {
			return nil, fmt.Errorf("restrict host key %s: %w", path, err)
		}
		signers = append(signers, signer)
		byKey[string(signer.PublicKey().Marshal())] = signer
	}
	for _, path := range certPaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read host certificate %s: %w", path, err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse host certificate %s: %w", path, err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("%s is not an SSH certificate", path)
		}
		var base ssh.Signer
		for _, signer := range byKey {
			if bytes.Equal(signer.PublicKey().Marshal(), cert.Key.Marshal()) {
				base = signer
				break
			}
		}
		if base == nil {
			return nil, fmt.Errorf("host certificate %s has no matching private host key", path)
		}
		cs, err := ssh.NewCertSigner(cert, base)
		if err != nil {
			return nil, fmt.Errorf("host certificate %s: %w", path, err)
		}
		signers = append(signers, cs)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no usable host keys")
	}
	return signers, nil
}

func checkRSASize(key ssh.PublicKey, minimum int) error {
	if minimum <= 0 {
		return nil
	}
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}
	cpk, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return nil
	}
	pub, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return nil
	}
	if pub.N.BitLen() < minimum {
		return fmt.Errorf("RSA key is %d bits, minimum is %d", pub.N.BitLen(), minimum)
	}
	return nil
}

func restrictSigner(signer ssh.Signer, allowed map[string]bool) (ssh.Signer, error) {
	var algos []string
	switch signer.PublicKey().Type() {
	case ssh.KeyAlgoED25519:
		algos = []string{ssh.KeyAlgoED25519}
	case ssh.KeyAlgoECDSA256:
		algos = []string{ssh.KeyAlgoECDSA256}
	case ssh.KeyAlgoECDSA384:
		algos = []string{ssh.KeyAlgoECDSA384}
	case ssh.KeyAlgoECDSA521:
		algos = []string{ssh.KeyAlgoECDSA521}
	case ssh.KeyAlgoRSA:
		algos = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	default:
		return nil, fmt.Errorf("unsupported host key type %q", signer.PublicKey().Type())
	}
	var filtered []string
	for _, a := range algos {
		if allowed[a] {
			filtered = append(filtered, a)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("host key type %q not allowed by HostKeyAlgorithms", signer.PublicKey().Type())
	}
	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("host key signer does not support algorithm selection")
	}
	if len(filtered) == len(algos) && signer.PublicKey().Type() != ssh.KeyAlgoRSA {
		return signer, nil
	}
	return ssh.NewSignerWithAlgorithms(as, filtered)
}

func ValidateCertAlgorithms(allowed []string) error {
	for _, a := range allowed {
		if strings.HasSuffix(a, "-cert-v01@openssh.com") && insecure[a] {
			return fmt.Errorf("unsupported certificate algorithm %q", a)
		}
	}
	return nil
}
