package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

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
