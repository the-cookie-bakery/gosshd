//go:build e2e

package smoke

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
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
	_, hostPath := sshdtest.NewHostKey(t, dir)
	clientSigner, _ := sshdtest.NewKey(t)
	u := sshdtest.NewUser(t)
	u.WriteAuthorizedKeys(t, clientSigner.PublicKey())
	port := sshdtest.FreePort(t)
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
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", cfg)
	sshdtest.Start(t, bin, cfgPath, port)

	client := sshdtest.Dial(t, port, sshdtest.ClientConfig(u.Name, ssh.Password(u.Password)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()

	client = sshdtest.Dial(t, port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(clientSigner)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	testPTY(t, client, u.Name)
	testConcurrentSessions(t, client, u.Name)
	testSignal(t, client)
	testSFTP(t, client, u.Home)
	client.Close()
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

func testConcurrentSessions(t *testing.T, client *ssh.Client, want string) {
	t.Helper()
	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Start("sleep 10"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	errCh := make(chan error, 1)
	go func() {
		second, err := client.NewSession()
		if err != nil {
			errCh <- err
			return
		}
		defer second.Close()
		out, err := second.CombinedOutput("id -un")
		if err != nil {
			errCh <- fmt.Errorf("second session: %v: %s", err, out)
			return
		}
		if strings.TrimSpace(string(out)) != want {
			errCh <- fmt.Errorf("second session got %q, want %q", strings.TrimSpace(string(out)), want)
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second session blocked behind first session")
	}
}

func testSignal(t *testing.T, client *ssh.Client) {
	t.Helper()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Start("sleep 30"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := s.Signal(ssh.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = s.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not terminate after signal")
	}
}

func testSFTP(t *testing.T, client *ssh.Client, home string) {
	t.Helper()
	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	path := home + "/sftp-test"
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
