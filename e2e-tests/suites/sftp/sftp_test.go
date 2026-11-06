//go:build e2e

package sftp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
)

func setup(t *testing.T, extra string) (*sshdtest.Server, *sshdtest.User, ssh.Signer) {
	t.Helper()
	return setupFor(t, func(*sshdtest.User) string { return extra })
}

func setupFor(t *testing.T, extra func(*sshdtest.User) string) (*sshdtest.Server, *sshdtest.User, ssh.Signer) {
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
	signer, _ := sshdtest.NewKey(t)
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
StrictModes yes
LogLevel DEBUG
%s`, port, hostPath, extra(u))
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", cfg)
	return sshdtest.Start(t, bin, cfgPath, port), u, signer
}

func TestExternalSubsystem(t *testing.T) {
	srv, u, signer := setup(t, "Subsystem echo /bin/echo external-subsystem\n")
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestSubsystem("echo"); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	_ = session.Wait()
	if !strings.Contains(string(data), "external-subsystem") {
		t.Fatalf("subsystem output=%q", data)
	}
}

func TestChrootSFTP(t *testing.T) {
	chroot, err := os.MkdirTemp("/", "gosshd-sftp-chroot-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(chroot, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(chroot)

	srv, u, signer := setupFor(t, func(u *sshdtest.User) string {
		return fmt.Sprintf("ChrootDirectory %s\nSubsystem sftp internal-sftp -d /home/%s\n", chroot, u.Name)
	})
	homeRoot := filepath.Join(chroot, "home")
	if err := os.MkdirAll(homeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(homeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(homeRoot, u.Name)
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, u.UID, u.GID); err != nil {
		t.Fatal(err)
	}

	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	sc, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	f, err := sc.Create("chroot-file")
	if err != nil {
		sc.Close()
		client.Close()
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("chrooted\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_ = sc.Close()
	client.Close()

	raw, err := os.ReadFile(filepath.Join(home, "chroot-file"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "chrooted\n" {
		t.Fatalf("content=%q", raw)
	}
}

func TestReadOnlySFTP(t *testing.T) {
	srv, u, signer := setup(t, "Subsystem sftp internal-sftp -R\n")
	existing := filepath.Join(u.Home, "existing.txt")
	if err := os.WriteFile(existing, []byte("readable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(existing, u.UID, u.GID); err != nil {
		t.Fatal(err)
	}

	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	if f, err := sc.Create("new-file"); err == nil {
		f.Close()
		t.Fatal("read-only SFTP allowed file creation")
	}
	f, err := sc.Open("existing.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "readable\n" {
		t.Fatalf("content=%q", raw)
	}
}
