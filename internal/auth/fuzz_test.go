package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/nss"
)

func FuzzScanAuthorizedKeys(f *testing.F) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	key := priv.Public().(ed25519.PublicKey)
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(ssh.MarshalAuthorizedKey(pub)))
	f.Add([]byte(`command="echo hi" ` + string(ssh.MarshalAuthorizedKey(pub))))
	f.Add([]byte("# comment\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _, _ = scanAuthorizedKeys(bytes.NewReader(data), pub, &nss.User{Name: "alice", Home: "/home/alice"}, nil)
	})
}

func FuzzParseCertificate(f *testing.F) {
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		f.Fatal(err)
	}
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	sshUserPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		f.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:             sshUserPub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		f.Fatal(err)
	}
	f.Add(ssh.MarshalAuthorizedKey(cert))
	f.Add(ssh.MarshalAuthorizedKey(sshUserPub))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return
		}
		_ = pub.Marshal()
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return
		}
		_ = cert.Marshal()
		_, _ = certificatePermissions(cert, nil)
		_ = caSignatureAllowed(cert, nil)
	})
}
