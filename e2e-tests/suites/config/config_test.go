//go:build e2e

package config

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
)

func testConfig(t *testing.T, bin, cfgPath string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, "-t", "-f", cfgPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	t.Fatalf("run -t: %v", err)
	return "", -1
}

func TestIncludeAccepted(t *testing.T) {
	bin := requireBin(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	sshdtest.WriteFile(t, dir, "included.conf", "PasswordAuthentication no\n")
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", fmt.Sprintf("Port 2222\nHostKey %s\nInclude included.conf\n", hostPath))
	if out, code := testConfig(t, bin, cfgPath); code != 0 {
		t.Fatalf("include config rejected (%d): %s", code, out)
	}
}

func TestRecursiveIncludeRejected(t *testing.T) {
	bin := requireBin(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	sshdtest.WriteFile(t, dir, "a.conf", "Include b.conf\n")
	sshdtest.WriteFile(t, dir, "b.conf", "Include a.conf\n")
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", fmt.Sprintf("HostKey %s\nInclude a.conf\n", hostPath))
	if out, code := testConfig(t, bin, cfgPath); code == 0 {
		t.Fatalf("recursive include accepted: %s", out)
	}
}

func TestUnsupportedDirectivesRejected(t *testing.T) {
	bin := requireBin(t)
	for name, body := range map[string]string{
		"unknown":     "DefinitelyNotAKeyword yes\n",
		"weak-cipher": "Ciphers aes128-cbc\n",
		"authmethods": "AuthenticationMethods publickey,bogus\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			_, hostPath := sshdtest.NewHostKey(t, dir)
			cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", fmt.Sprintf("HostKey %s\n%s", hostPath, body))
			if out, code := testConfig(t, bin, cfgPath); code == 0 {
				t.Fatalf("config accepted: %s", out)
			}
		})
	}
}

func TestAuthenticationMethodsAccepted(t *testing.T) {
	bin := requireBin(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", fmt.Sprintf("HostKey %s\nPasswordAuthentication yes\nPubkeyAuthentication yes\nAuthenticationMethods publickey,password\n", hostPath))
	if out, code := testConfig(t, bin, cfgPath); code != 0 {
		t.Fatalf("AuthenticationMethods config rejected (%d): %s", code, out)
	}
}

func TestDumpDefaults(t *testing.T) {
	bin := requireBin(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", fmt.Sprintf("HostKey %s\n", hostPath))
	cmd := exec.Command(bin, "-T", "-f", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("-T: %v: %s", err, out)
	}
	if !strings.Contains(string(out), `"RequiredRSASize": 2048`) {
		t.Fatalf("RequiredRSASize default missing: %s", out)
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
