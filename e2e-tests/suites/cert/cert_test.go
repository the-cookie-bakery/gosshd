//go:build e2e

package cert

import (
	"crypto/rand"
	"fmt"
	"os"
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

func requireBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("GOSSHD_BIN")
	if bin == "" {
		t.Fatal("GOSSHD_BIN is not set")
	}
	return bin
}

func signCert(t *testing.T, ca ssh.Signer, pub ssh.PublicKey, certType uint32, principals []string, critical, extensions map[string]string) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key:             pub,
		CertType:        certType,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions:     ssh.Permissions{CriticalOptions: critical, Extensions: extensions},
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func writePublic(t *testing.T, dir, name string, key ssh.PublicKey) string {
	t.Helper()
	path := dir + "/" + name
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startServer(t *testing.T, dir, hostPath, extra string) *sshdtest.Server {
	t.Helper()
	port := sshdtest.FreePort(t)
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
AuthorizedKeysFile none
StrictModes yes
LogLevel DEBUG
%s`, port, hostPath, extra)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", cfg)
	return sshdtest.Start(t, requireBin(t), cfgPath, port)
}

func TestUserCertificate(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	caSigner, _ := sshdtest.NewKey(t)
	userSigner, _ := sshdtest.NewKey(t)
	caPath := writePublic(t, dir, "user_ca.pub", caSigner.PublicKey())
	srv := startServer(t, dir, hostPath, fmt.Sprintf("TrustedUserCAKeys %s\n", caPath))

	good := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{u.Name}, nil, nil)
	goodSigner, err := ssh.NewCertSigner(good, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(goodSigner)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()

	bad := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{"someone-else"}, nil, nil)
	badSigner, err := ssh.NewCertSigner(bad, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(badSigner)))
	if err == nil {
		c.Close()
		t.Fatal("certificate with wrong principal was accepted")
	}
}

func TestRevokedCertificate(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	caSigner, _ := sshdtest.NewKey(t)
	userSigner, _ := sshdtest.NewKey(t)
	caPath := writePublic(t, dir, "user_ca.pub", caSigner.PublicKey())
	revokedPath := writePublic(t, dir, "revoked_keys", userSigner.PublicKey())
	srv := startServer(t, dir, hostPath, fmt.Sprintf("TrustedUserCAKeys %s\nRevokedKeys %s\n", caPath, revokedPath))

	cert := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{u.Name}, nil, nil)
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(certSigner)))
	if err == nil {
		c.Close()
		t.Fatal("revoked certificate was accepted")
	}
}

func TestAuthorizedPrincipalsFile(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	caSigner, _ := sshdtest.NewKey(t)
	userSigner, _ := sshdtest.NewKey(t)
	caPath := writePublic(t, dir, "user_ca.pub", caSigner.PublicKey())
	principalsPath := dir + "/principals"
	if err := os.WriteFile(principalsPath, []byte("cert-principal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, dir, hostPath, fmt.Sprintf("TrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s\n", caPath, principalsPath))

	cert := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{"cert-principal"}, nil, nil)
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(certSigner)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()
}

func TestAuthorizedKeysCertAuthority(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	caSigner, _ := sshdtest.NewKey(t)
	userSigner, _ := sshdtest.NewKey(t)
	line := append([]byte(fmt.Sprintf(`cert-authority,principals="%s" `, u.Name)), ssh.MarshalAuthorizedKey(caSigner.PublicKey())...)
	u.WriteAuthorizedKeysRaw(t, line)
	srv := startServer(t, dir, hostPath, "AuthorizedKeysFile .ssh/authorized_keys\n")

	cert := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{u.Name}, nil, nil)
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(certSigner)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()

	bad := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{"other"}, nil, nil)
	badSigner, err := ssh.NewCertSigner(bad, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(badSigner)))
	if err == nil {
		c.Close()
		t.Fatal("cert-authority accepted a certificate with the wrong principal")
	}
}

func TestCertificateForceCommand(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	caSigner, _ := sshdtest.NewKey(t)
	userSigner, _ := sshdtest.NewKey(t)
	caPath := writePublic(t, dir, "user_ca.pub", caSigner.PublicKey())
	srv := startServer(t, dir, hostPath, fmt.Sprintf("TrustedUserCAKeys %s\n", caPath))

	cert := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{u.Name}, map[string]string{"force-command": "echo cert-command"}, nil)
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(certSigner)))
	defer client.Close()
	sshdtest.MustRun(t, client, "id", "cert-command")
}

func TestHostCertificate(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	hostSigner, hostPath := sshdtest.NewHostKey(t, dir)
	caSigner, _ := sshdtest.NewKey(t)
	hostCert := signCert(t, caSigner, hostSigner.PublicKey(), ssh.HostCert, []string{"localhost"}, nil, nil)
	hostCertPath := writePublic(t, dir, "ssh_host_ed25519_key-cert.pub", hostCert)
	u := sshdtest.NewUser(t)
	signer, _ := sshdtest.NewKey(t)
	u.WriteAuthorizedKeys(t, signer.PublicKey())
	srv := startServer(t, dir, hostPath, fmt.Sprintf("HostCertificate %s\nAuthorizedKeysFile .ssh/authorized_keys\n", hostCertPath))

	cfg := sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer))
	cfg.HostKeyAlgorithms = []string{ssh.CertAlgoED25519v01}
	cfg.HostKeyCallback = ssh.FixedHostKey(hostCert)
	client := sshdtest.Dial(t, srv.Port, cfg)
	defer client.Close()
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
}

func TestAuthorizedPrincipalsCommand(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	u := sshdtest.NewUser(t)
	caSigner, _ := sshdtest.NewKey(t)
	userSigner, _ := sshdtest.NewKey(t)
	caPath := writePublic(t, dir, "user_ca.pub", caSigner.PublicKey())
	script := dir + "/principals-command.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho cert-principal\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	extra := fmt.Sprintf("TrustedUserCAKeys %s\nAuthorizedPrincipalsCommand %s\nAuthorizedPrincipalsCommandUser root\n", caPath, script)
	srv := startServer(t, dir, hostPath, extra)

	cert := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{"cert-principal"}, nil, nil)
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	client := sshdtest.Dial(t, srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(certSigner)))
	sshdtest.MustRunAs(t, client, "id -un", u.Name)
	client.Close()

	bad := signCert(t, caSigner, userSigner.PublicKey(), ssh.UserCert, []string{"other-principal"}, nil, nil)
	badSigner, err := ssh.NewCertSigner(bad, userSigner)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshdtest.TryDial(srv.Port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(badSigner)))
	if err == nil {
		c.Close()
		t.Fatal("principal not returned by command was accepted")
	}
}
