//go:build e2e

package interop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
)

type env struct {
	port    int
	user    *sshdtest.User
	signer  ssh.Signer
	keyPath string
	dir     string
}

func setup(t *testing.T) *env {
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
	u := sshdtest.NewUser(t)
	signer, priv := sshdtest.NewKey(t)
	keyPath := filepath.Join(dir, "client_key")
	sshdtest.WritePrivateKey(t, keyPath, priv)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	port := sshdtest.FreePort(t)
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp internal-sftp
StrictModes yes
ClientAliveInterval 1
ClientAliveCountMax 3
LogLevel DEBUG
`, port, hostPath)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", cfg)
	sshdtest.Start(t, bin, cfgPath, port)
	return &env{port: port, user: u, signer: signer, keyPath: keyPath, dir: dir}
}

func (e *env) sshArgs(extra ...string) []string {
	args := []string{
		"-i", e.keyPath,
		"-p", strconv.Itoa(e.port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
	}
	return append(args, extra...)
}

func (e *env) transferArgs(extra ...string) []string {
	args := []string{
		"-i", e.keyPath,
		"-P", strconv.Itoa(e.port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
	}
	return append(args, extra...)
}

func (e *env) ssh(t *testing.T, command string, extra ...string) (string, int) {
	t.Helper()
	args := e.sshArgs(extra...)
	args = append(args, e.user.Name+"@127.0.0.1", command)
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	t.Fatalf("ssh: %v: %s", err, out)
	return "", -1
}

func TestSSHCommandAndExitStatus(t *testing.T) {
	e := setup(t)
	out, code := e.ssh(t, "id -un")
	if code != 0 {
		t.Fatalf("ssh id failed (%d): %s", code, out)
	}
	if strings.TrimSpace(out) != e.user.Name {
		t.Fatalf("got %q, want %q", strings.TrimSpace(out), e.user.Name)
	}

	out, code = e.ssh(t, "exit 7")
	if code != 7 {
		t.Fatalf("exit status got %d, want 7: %s", code, out)
	}
}

func TestSSHPTY(t *testing.T) {
	e := setup(t)
	out, code := e.ssh(t, "id -un", "-tt")
	if code != 0 {
		t.Fatalf("ssh -tt failed (%d): %s", code, out)
	}
	if strings.TrimSpace(out) != e.user.Name {
		t.Fatalf("pty got %q, want %q", strings.TrimSpace(out), e.user.Name)
	}
}

func TestSCPAndSFTP(t *testing.T) {
	e := setup(t)
	local := filepath.Join(e.dir, "local.txt")
	if err := os.WriteFile(local, []byte("interop scp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := e.user.Home + "/scp-target.txt"
	args := e.transferArgs()
	args = append(args, local, e.user.Name+"@127.0.0.1:"+remote)
	if out, err := exec.Command("scp", args...).CombinedOutput(); err != nil {
		t.Fatalf("scp: %v: %s", err, out)
	}
	raw, err := os.ReadFile(remote)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "interop scp\n" {
		t.Fatalf("scp content=%q", raw)
	}

	sftpRemote := e.user.Home + "/sftp-target.txt"
	sftpLocal := filepath.Join(e.dir, "sftp-back.txt")
	batch := filepath.Join(e.dir, "sftp.batch")
	batchData := fmt.Sprintf("put %s %s\nget %s %s\n", local, sftpRemote, sftpRemote, sftpLocal)
	if err := os.WriteFile(batch, []byte(batchData), 0o600); err != nil {
		t.Fatal(err)
	}
	args = e.transferArgs("-b", batch)
	args = append(args, e.user.Name+"@127.0.0.1")
	if out, err := exec.Command("sftp", args...).CombinedOutput(); err != nil {
		t.Fatalf("sftp: %v: %s", err, out)
	}
	raw, err = os.ReadFile(sftpLocal)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "interop scp\n" {
		t.Fatalf("sftp content=%q", raw)
	}
}

func TestClientAliveKeepsSession(t *testing.T) {
	e := setup(t)
	out, code := e.ssh(t, "sleep 3; id -un")
	if code != 0 {
		t.Fatalf("session with client-alive failed (%d): %s", code, out)
	}
	if strings.TrimSpace(out) != e.user.Name {
		t.Fatalf("got %q, want %q", strings.TrimSpace(out), e.user.Name)
	}
}

func TestNoMoreSessions(t *testing.T) {
	e := setup(t)
	client := sshdtest.Dial(t, e.port, sshdtest.ClientConfig(e.user.Name, ssh.PublicKeys(e.signer)))
	defer client.Close()
	ok, _, err := client.SendRequest("no-more-sessions@openssh.com", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("no-more-sessions request was rejected")
	}
	if session, err := client.NewSession(); err == nil {
		session.Close()
		t.Fatal("new session accepted after no-more-sessions")
	}
}

func TestForwardingRejected(t *testing.T) {
	e := setup(t)
	client := sshdtest.Dial(t, e.port, sshdtest.ClientConfig(e.user.Name, ssh.PublicKeys(e.signer)))
	defer client.Close()

	if c, err := client.Dial("tcp", "127.0.0.1:22"); err == nil {
		c.Close()
		t.Fatal("direct-tcpip channel was accepted")
	}
	if l, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		l.Close()
		t.Fatal("remote tcpip-forward was accepted")
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	x11Payload := ssh.Marshal(struct {
		SingleConnection bool
		AuthProtocol     string
		AuthCookie       string
		ScreenNumber     uint32
	}{false, "MIT-MAGIC-COOKIE-1", "00", 0})
	if ok, err := session.SendRequest("x11-req", true, x11Payload); err != nil || ok {
		t.Fatalf("x11-req accepted: ok=%v err=%v", ok, err)
	}
	if ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil); err != nil || ok {
		t.Fatalf("agent forwarding accepted: ok=%v err=%v", ok, err)
	}
}
