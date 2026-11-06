//go:build e2e

package smoke

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestPasswordAndKeySession(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root inside the test container")
	}
	bin := os.Getenv("GOSSHD_BIN")
	if bin == "" {
		t.Fatal("GOSSHD_BIN is not set")
	}
	dir := t.TempDir()
	hostSigner, hostKey := newKey(t)
	clientSigner, _ := newKey(t)
	hostPath := filepath.Join(dir, "ssh_host_ed25519_key")
	writePrivateKey(t, hostPath, hostKey)
	name := fmt.Sprintf("gs%06d", time.Now().UnixNano()%1000000)
	password := "e2e-password"
	createUser(t, name, password)
	home := userHome(t, name)
	writeAuthorizedKey(t, name, home, clientSigner.PublicKey())
	port := freePort(t)
	cfgPath := filepath.Join(dir, "sshd_config")
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
PermitRootLogin no
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp internal-sftp
StrictModes yes
LogLevel DEBUG
`, port, hostPath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "gosshd.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-D", "-f", cfgPath, "-e")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		logFile.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(logPath)
			t.Logf("gosshd log:\n%s", raw)
		}
	})
	waitPort(t, port, 10*time.Second)
	clientCfg := &ssh.ClientConfig{
		User:            name,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client := dial(t, port, clientCfg)
	runID(t, client, name)
	client.Close()
	clientCfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}
	client = dial(t, port, clientCfg)
	runID(t, client, name)
	testPTY(t, client, name)
	testSFTP(t, client, home)
	client.Close()
	_ = hostSigner
}

func testPTY(t *testing.T, client *ssh.Client, want string) {
	t.Helper()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	out, err := s.CombinedOutput("id -un")
	if err != nil {
		t.Fatalf("pty run: %v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != want {
		t.Fatalf("pty got %q, want %q", string(out), want)
	}
}

func testSFTP(t *testing.T, client *ssh.Client, home string) {
	t.Helper()
	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	path := filepath.Join(home, "sftp-test")
	f, err := sc.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hello sftp\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := sc.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "hello sftp\n" {
		t.Fatalf("sftp content=%q", raw)
	}
}

func newKey(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

func writePrivateKey(t *testing.T, path string, key ed25519.PrivateKey) {
	t.Helper()
	pemBlock, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatal(err)
	}
}

func createUser(t *testing.T, name, password string) {
	t.Helper()
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/sh", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(name + ":" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("chpasswd: %v: %s", err, out)
	}
}

func userHome(t *testing.T, name string) string {
	t.Helper()
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return u.HomeDir
}

func writeAuthorizedKey(t *testing.T, name, home string, key ssh.PublicKey) {
	t.Helper()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.Chown(sshDir, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d did not become ready", port)
}

func dial(t *testing.T, port int, cfg *ssh.ClientConfig) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func runID(t *testing.T, client *ssh.Client, want string) {
	t.Helper()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out, err := s.CombinedOutput("id -un")
	if err != nil {
		t.Fatalf("run: %v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != want {
		t.Fatalf("got %q, want %q", string(out), want)
	}
}
