//go:build e2e

package auth

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
)

func startServer(t *testing.T, u *sshdtest.User, extra string) *sshdtest.Server {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root inside the test container")
	}
	bin := os.Getenv("GOSSHD_BIN")
	if bin == "" {
		t.Fatal("GOSSHD_BIN is not set")
	}
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	port := sshdtest.FreePort(t)
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
LogLevel DEBUG
%s`, port, hostPath, extra)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", cfg)
	return sshdtest.Start(t, bin, cfgPath, port)
}

func TestWrongPasswordRejected(t *testing.T) {
	u := sshdtest.NewUser(t)
	srv := startServer(t, u, "")
	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password("wrong-password")))
	if err == nil {
		client.Close()
		t.Fatal("wrong password was accepted")
	}
	client = sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	defer client.Close()
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
}

func TestLockedAccountRejected(t *testing.T) {
	u := sshdtest.NewUser(t)
	sshdtest.LockUser(t, u.Name)
	srv := startServer(t, u, "")
	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		client.Close()
		t.Fatal("locked account was accepted")
	}
}

func TestExpiredAccountRejected(t *testing.T) {
	u := sshdtest.NewUser(t)
	sshdtest.ExpireUser(t, u.Name)
	srv := startServer(t, u, "")
	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		client.Close()
		t.Fatal("expired account was accepted")
	}
}

func TestDeniedAndAllowedUsers(t *testing.T) {
	u := sshdtest.NewUser(t)
	srv := startServer(t, u, "DenyUsers "+u.Name+"\n")
	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		client.Close()
		t.Fatal("denied user was accepted")
	}

	srv = startServer(t, u, "AllowUsers someone-else\n")
	client, err = sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		client.Close()
		t.Fatal("user not in AllowUsers was accepted")
	}
}

func TestPublicKeyNotAuthorized(t *testing.T) {
	u := sshdtest.NewUser(t)
	clientSigner, _ := sshdtest.NewKey(t)
	srv := startServer(t, u, "")
	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(clientSigner)))
	if err == nil {
		client.Close()
		t.Fatal("unauthorized key was accepted")
	}
}

func TestAuthorizedKeyOptions(t *testing.T) {
	t.Run("from mismatch", func(t *testing.T) {
		u := sshdtest.NewUser(t)
		signer, _ := sshdtest.NewKey(t)
		u.WriteAuthorizedKeysRaw(t, append([]byte(`from="192.0.2.1" `), ssh.MarshalAuthorizedKey(signer.PublicKey())...))
		srv := startServer(t, u, "")
		client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
		if err == nil {
			client.Close()
			t.Fatal("key with mismatched from was accepted")
		}
	})

	t.Run("forced command", func(t *testing.T) {
		u := sshdtest.NewUser(t)
		signer, _ := sshdtest.NewKey(t)
		u.WriteAuthorizedKeysRaw(t, append([]byte(`command="echo forced-command" `), ssh.MarshalAuthorizedKey(signer.PublicKey())...))
		srv := startServer(t, u, "")
		client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
		defer client.Close()
		sshdtest.MustRun(t, client, "id", "forced-command")
	})

	t.Run("no-pty", func(t *testing.T) {
		u := sshdtest.NewUser(t)
		signer, _ := sshdtest.NewKey(t)
		u.WriteAuthorizedKeysRaw(t, append([]byte(`no-pty `), ssh.MarshalAuthorizedKey(signer.PublicKey())...))
		srv := startServer(t, u, "")
		client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
		defer client.Close()
		s, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
			t.Fatal("pty request succeeded despite no-pty")
		}
	})

	t.Run("expired key", func(t *testing.T) {
		u := sshdtest.NewUser(t)
		signer, _ := sshdtest.NewKey(t)
		u.WriteAuthorizedKeysRaw(t, append([]byte(`expiry-time="20200101000000" `), ssh.MarshalAuthorizedKey(signer.PublicKey())...))
		srv := startServer(t, u, "")
		client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
		if err == nil {
			client.Close()
			t.Fatal("expired key was accepted")
		}
	})
}

func TestPasswordAuthenticationDisabled(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, u, "PasswordAuthentication no\n")

	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		client.Close()
		t.Fatal("password auth succeeded while disabled")
	}
	client = sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
}

func TestKeyboardInteractiveGating(t *testing.T) {
	answer := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		out := make([]string, len(questions))
		for i := range out {
			out[i] = "e2e-password"
		}
		return out, nil
	}

	u := sshdtest.NewUser(t)
	srv := startServer(t, u, "")
	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.KeyboardInteractive(answer)))
	if err != nil {
		t.Fatalf("keyboard-interactive with default config: %v", err)
	}
	client.Close()

	srv = startServer(t, u, "KbdInteractiveAuthentication no\nPasswordAuthentication no\n")
	client, err = sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.KeyboardInteractive(answer)))
	if err == nil {
		client.Close()
		t.Fatal("keyboard-interactive succeeded while disabled")
	}
}

func TestUnknownUserRejected(t *testing.T) {
	u := sshdtest.NewUser(t)
	srv := startServer(t, u, "")
	client, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(strings.TrimSpace(u.Name+"-missing"), ssh.Password("whatever")))
	if err == nil {
		client.Close()
		t.Fatal("unknown user was accepted")
	}
}
