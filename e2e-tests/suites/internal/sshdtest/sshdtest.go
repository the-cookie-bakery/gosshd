package sshdtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
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

	"golang.org/x/crypto/ssh"
)

type Server struct {
	Port    int
	PID     int
	Dir     string
	LogPath string
	cmd     *exec.Cmd
	logFile *os.File
}

type User struct {
	Name     string
	Password string
	Home     string
	UID      int
	GID      int
}

func NewKey(t testing.TB) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, priv
}

func WritePrivateKey(t testing.TB, path string, key ed25519.PrivateKey) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

func NewHostKey(t testing.TB, dir string) (ssh.Signer, string) {
	t.Helper()
	signer, priv := NewKey(t)
	path := filepath.Join(dir, "ssh_host_ed25519_key")
	WritePrivateKey(t, path, priv)
	return signer, path
}

func FreePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func WriteFile(t testing.TB, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func Start(t testing.TB, bin, configPath string, port int) *Server {
	t.Helper()
	dir := filepath.Dir(configPath)
	logPath := filepath.Join(dir, "gosshd.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-D", "-f", configPath, "-e")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &Server{Port: port, PID: cmd.Process.Pid, Dir: dir, LogPath: logPath, cmd: cmd, logFile: logFile}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		logFile.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(logPath)
			t.Logf("gosshd log:\n%s", raw)
		}
	})
	WaitPort(t, port, 10*time.Second)
	return s
}

func WaitPort(t testing.TB, port int, timeout time.Duration) {
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

func ClientConfig(username string, auth ...ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

func Dial(t testing.TB, port int, cfg *ssh.ClientConfig) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TryDial(port int, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
}

func NewUser(t testing.TB) *User {
	t.Helper()
	name := fmt.Sprintf("gs%06d", time.Now().UnixNano()%1000000)
	password := "e2e-password"
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/sh", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v: %s", err, out)
	}
	u := lookupUser(t, name)
	u.Password = password
	SetPassword(t, name, password)
	return u
}

func lookupUser(t testing.TB, name string) *User {
	t.Helper()
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return &User{Name: name, Home: u.HomeDir, UID: uid, GID: gid}
}

func SetPassword(t testing.TB, name, password string) {
	t.Helper()
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(name + ":" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("chpasswd: %v: %s", err, out)
	}
}

func LockUser(t testing.TB, name string) {
	t.Helper()
	if out, err := exec.Command("usermod", "-L", name).CombinedOutput(); err != nil {
		t.Fatalf("usermod -L: %v: %s", err, out)
	}
}

func ExpireUser(t testing.TB, name string) {
	t.Helper()
	if out, err := exec.Command("chage", "-E", "0", name).CombinedOutput(); err != nil {
		t.Fatalf("chage -E 0: %v: %s", err, out)
	}
}

func (u *User) WriteAuthorizedKeys(t testing.TB, keys ...ssh.PublicKey) {
	t.Helper()
	var data []byte
	for _, key := range keys {
		data = append(data, ssh.MarshalAuthorizedKey(key)...)
	}
	u.WriteAuthorizedKeysRaw(t, data)
}

func (u *User) WriteAuthorizedKeysRaw(t testing.TB, data []byte) {
	t.Helper()
	sshDir := filepath.Join(u.Home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(sshDir, u.UID, u.GID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, u.UID, u.GID); err != nil {
		t.Fatal(err)
	}
}

func Run(t testing.TB, client *ssh.Client, command string) (string, error) {
	t.Helper()
	s, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.CombinedOutput(command)
	return string(out), err
}

func MustRunAs(t testing.TB, client *ssh.Client, command, want string) {
	t.Helper()
	out, err := Run(t, client, command)
	if err != nil {
		t.Fatalf("run %q: %v: %s", command, err, out)
	}
	if strings.TrimSpace(out) != want {
		t.Fatalf("run %q got %q, want %q", command, strings.TrimSpace(out), want)
	}
}

func MustRun(t testing.TB, client *ssh.Client, command, want string) {
	t.Helper()
	out, err := Run(t, client, command)
	if err != nil {
		t.Fatalf("run %q: %v: %s", command, err, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("run %q got %q, want substring %q", command, out, want)
	}
}
