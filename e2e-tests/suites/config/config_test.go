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

func TestAuthorizedCommandValidation(t *testing.T) {
	bin := requireBin(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	valid := sshdtest.WriteFile(t, dir, "valid.conf", fmt.Sprintf("HostKey %s\nAuthorizedKeysCommand /bin/true\nAuthorizedKeysCommandUser root\nAuthorizedPrincipalsCommand /bin/true\nAuthorizedPrincipalsCommandUser root\n", hostPath))
	if out, code := testConfig(t, bin, valid); code != 0 {
		t.Fatalf("valid command config rejected (%d): %s", code, out)
	}
	missingUser := sshdtest.WriteFile(t, dir, "missing_user.conf", fmt.Sprintf("HostKey %s\nAuthorizedKeysCommand /bin/true\n", hostPath))
	if out, code := testConfig(t, bin, missingUser); code == 0 {
		t.Fatalf("command without user accepted: %s", out)
	}
	missingPath := sshdtest.WriteFile(t, dir, "missing_path.conf", fmt.Sprintf("HostKey %s\nAuthorizedKeysCommand /definitely/not/here\nAuthorizedKeysCommandUser root\n", hostPath))
	if out, code := testConfig(t, bin, missingPath); code == 0 {
		t.Fatalf("missing command path accepted: %s", out)
	}
}

func TestMatchConfigAccepted(t *testing.T) {
	bin := requireBin(t)
	dir := t.TempDir()
	_, hostPath := sshdtest.NewHostKey(t, dir)
	valid := sshdtest.WriteFile(t, dir, "match.conf", fmt.Sprintf("HostKey %s\nMatch User alice\n    PermitTTY no\n    ForceCommand \"echo hi\"\n", hostPath))
	if out, code := testConfig(t, bin, valid); code != 0 {
		t.Fatalf("valid Match config rejected (%d): %s", code, out)
	}
	invalid := sshdtest.WriteFile(t, dir, "match_invalid.conf", fmt.Sprintf("HostKey %s\nMatch User alice\n    Port 2222\n", hostPath))
	if out, code := testConfig(t, bin, invalid); code == 0 {
		t.Fatalf("unsupported Match directive accepted: %s", out)
	}
}
