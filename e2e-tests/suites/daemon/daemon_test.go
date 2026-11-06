//go:build e2e

package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root inside the test container")
	}
}

func binPath(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("GOSSHD_BIN")
	if bin == "" {
		t.Fatal("GOSSHD_BIN is not set")
	}
	return bin
}

func baseConfig(hostPath string, port int) string {
	prefix := ""
	if port != 0 {
		prefix = fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\n", port)
	}
	return prefix + fmt.Sprintf(`HostKey %s
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
LogLevel DEBUG
`, hostPath)
}

func TestSIGHUPReload(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	port := sshdtest.FreePort(t)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", baseConfig(hostPath, port)+"ForceCommand \"echo before\"\n")
	srv := sshdtest.Start(t, binPath(t), cfgPath, port)

	oldClient := sshdtest.Dial(t, port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer oldClient.Close()
	sshdtest.MustRun(t, oldClient, "id", "before")

	newConfig := strings.Replace(baseConfig(hostPath, port)+"ForceCommand \"echo after\"\n", "echo before", "echo after", 1)
	if err := os.WriteFile(cfgPath, []byte(newConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(srv.PID, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		client, err := sshdtest.TryDial(port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
		if err == nil {
			out, runErr := sshdtest.Run(t, client, "id")
			client.Close()
			if runErr == nil && strings.Contains(out, "after") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("reloaded ForceCommand was not applied")
		}
		time.Sleep(100 * time.Millisecond)
	}

	sshdtest.MustRun(t, oldClient, "id", "before")
}

func TestReloadRejectsListenerChanges(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	port := sshdtest.FreePort(t)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", baseConfig(hostPath, port)+"ForceCommand \"echo before\"\n")
	srv := sshdtest.Start(t, binPath(t), cfgPath, port)

	newPort := sshdtest.FreePort(t)
	changed := strings.Replace(baseConfig(hostPath, port)+"ForceCommand \"echo before\"\n", fmt.Sprintf("Port %d", port), fmt.Sprintf("Port %d", newPort), 1)
	if err := os.WriteFile(cfgPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(srv.PID, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	client := sshdtest.Dial(t, port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	sshdtest.MustRun(t, client, "id", "before")
}

func TestInetdMode(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", baseConfig(hostPath, 0))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	logPath := filepath.Join(dir, "inetd.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	cmd := exec.Command(binPath(t), "-i", "-f", cfgPath)
	cmd.Stderr = logFile
	started := make(chan error, 1)
	waited := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			started <- err
			return
		}
		file, err := conn.(*net.TCPConn).File()
		conn.Close()
		if err != nil {
			started <- err
			return
		}
		cmd.Stdin = file
		cmd.Stdout = file
		if err := cmd.Start(); err != nil {
			file.Close()
			started <- err
			return
		}
		file.Close()
		started <- nil
		waited <- cmd.Wait()
	}()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	client, err := ssh.Dial("tcp", listener.Addr().String(), sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	if err != nil {
		t.Fatal(err)
	}
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		raw, _ := os.ReadFile(logPath)
		t.Fatalf("inetd process did not exit: %s", raw)
	}
}

func TestLoginGraceTime(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	port := sshdtest.FreePort(t)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", baseConfig(hostPath, port)+"LoginGraceTime 1\n")
	sshdtest.Start(t, binPath(t), cfgPath, port)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("connection was not closed by LoginGraceTime")
		}
		return
	}
}
