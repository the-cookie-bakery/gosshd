//go:build e2e

package auth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestAuthenticationMethods(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, u, "AuthenticationMethods publickey,password\n")

	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer), ssh.Password(u.Password)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()

	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		c.Close()
		t.Fatal("password-only authentication was accepted")
	}

	c, err = sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	if err == nil {
		c.Close()
		t.Fatal("publickey-only authentication was accepted")
	}

	c, err = sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer), ssh.Password("wrong-password")))
	if err == nil {
		c.Close()
		t.Fatal("wrong second factor was accepted")
	}
}

func TestAuthorizedKeysCommand(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	dir := t.TempDir()
	keyPath := dir + "/authorized_keys"
	if err := os.WriteFile(keyPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	script := dir + "/keys-command.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat "+keyPath+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	extra := "AuthorizedKeysFile none\nAuthorizedKeysCommand " + script + "\nAuthorizedKeysCommandUser root\n"
	srv := startServer(t, u, extra)
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()

	otherSigner, _ := sshdtest.NewKey(t)
	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(otherSigner)))
	if err == nil {
		c.Close()
		t.Fatal("key not returned by command was accepted")
	}
}

func TestMatchUserPasswordDisabled(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, u, "Match User "+u.Name+"\n    PasswordAuthentication no\n")

	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		c.Close()
		t.Fatal("password authentication was accepted despite Match disable")
	}
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
}

func TestMatchAddressPasswordDisabled(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, u, "Match Address 127.0.0.0/8\n    PasswordAuthentication no\n")

	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	if err == nil {
		c.Close()
		t.Fatal("password authentication was accepted despite Match Address disable")
	}
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
}

func TestMatchForceCommandAndNoPTY(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, u, "Match User "+u.Name+"\n    ForceCommand \"echo matched-command\"\n    PermitTTY no\n")

	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	sshdtest.MustRun(t, client, "id", "matched-command")

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := session.Start("id"); err == nil {
		t.Fatal("PTY session started despite Match PermitTTY no")
	}
}

func TestUserRC(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	rcPath := filepath.Join(u.Home, ".ssh", "rc")
	if err := os.WriteFile(rcPath, []byte("#!/bin/sh\necho rc-ran > \"$HOME/rc-marker\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(rcPath, u.UID, u.GID); err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, u, "")
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	raw, err := os.ReadFile(filepath.Join(u.Home, "rc-marker"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "rc-ran" {
		t.Fatalf("rc marker=%q", raw)
	}

	u2 := sshdtest.NewUser(t)
	signer2, _ := sshdtest.NewKey(t)
	u2.WriteAuthorizedKeys(t, signer2.PublicKey())
	rcPath = filepath.Join(u2.Home, ".ssh", "rc")
	if err := os.WriteFile(rcPath, []byte("#!/bin/sh\necho rc-ran > \"$HOME/rc-marker\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(rcPath, u2.UID, u2.GID); err != nil {
		t.Fatal(err)
	}
	srv = startServer(t, u2, "PermitUserRC no\n")
	client = sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u2.Name, ssh.PublicKeys(signer2)))
	defer client.Close()
	sshdtest.MustRunAs(t, client, "id -un", u2.Name)
	if _, err := os.Stat(filepath.Join(u2.Home, "rc-marker")); err == nil {
		t.Fatal("rc ran despite PermitUserRC no")
	}
}

func TestMotdAndLastLog(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())

	motdBackup, motdErr := os.ReadFile("/etc/motd")
	const motdMarker = "gosshd-motd-marker"
	if err := os.WriteFile("/etc/motd", []byte(motdMarker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if motdErr == nil {
			_ = os.WriteFile("/etc/motd", motdBackup, 0o644)
		} else {
			_ = os.Remove("/etc/motd")
		}
	}()

	lastlogBackup, lastlogErr := os.ReadFile("/var/log/lastlog")
	const lastlogHost = "gosshd-lastlog.test"
	entry := make([]byte, 292)
	binary.LittleEndian.PutUint32(entry[0:4], uint32(time.Now().Unix()))
	copy(entry[36:292], []byte(lastlogHost))
	data := make([]byte, (u.UID+1)*292)
	copy(data[u.UID*292:], entry)
	if err := os.WriteFile("/var/log/lastlog", data, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if lastlogErr == nil {
			_ = os.WriteFile("/var/log/lastlog", lastlogBackup, 0o600)
		} else {
			_ = os.Remove("/var/log/lastlog")
		}
	}()

	srv := startServer(t, u, "")
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		var buf []byte
		tmp := make([]byte, 1024)
		for {
			n, err := out.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if bytes.Contains(buf, []byte(motdMarker)) && bytes.Contains(buf, []byte(lastlogHost)) {
					done <- string(buf)
					return
				}
			}
			if err != nil {
				done <- string(buf)
				return
			}
		}
	}()
	select {
	case got := <-done:
		if !strings.Contains(got, motdMarker) {
			t.Fatalf("motd not printed: %q", got)
		}
		if !strings.Contains(got, lastlogHost) {
			t.Fatalf("lastlog not printed: %q", got)
		}
	case <-time.After(5 * time.Second):
		_ = session.Close()
		t.Fatal("timed out waiting for motd/lastlog")
	}
}

func TestTerminalModes(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, u, "")
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	out, err := session.CombinedOutput("stty -a")
	if err != nil {
		t.Fatalf("stty: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "-echo") {
		t.Fatalf("ECHO was not disabled: %s", out)
	}
}

func TestMaxSessions(t *testing.T) {
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, u, "MaxSessions 1\n")
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Start("sleep 10"); err != nil {
		t.Fatal(err)
	}
	second, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.Start("id"); err == nil {
		t.Fatal("second session started despite MaxSessions 1")
	}
}
