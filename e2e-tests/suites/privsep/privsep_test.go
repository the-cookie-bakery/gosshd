//go:build e2e

package privsep

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
)

type procInfo struct {
	pid     int
	ppid    int
	uid     int
	cmdline string
}

func listProcs(t *testing.T) []procInfo {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var out []procInfo
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		info := procInfo{pid: pid, ppid: -1, uid: -1}
		for _, line := range strings.Split(string(status), "\n") {
			switch {
			case strings.HasPrefix(line, "PPid:"):
				fmt.Sscanf(line, "PPid:\t%d", &info.ppid)
			case strings.HasPrefix(line, "Uid:"):
				fields := strings.Fields(line)
				if len(fields) > 1 {
					info.uid, _ = strconv.Atoi(fields[1])
				}
			}
		}
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err == nil {
			info.cmdline = strings.ReplaceAll(string(raw), "\x00", " ")
		}
		out = append(out, info)
	}
	return out
}

func TestWorkerIsolation(t *testing.T) {
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
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
`, port, hostPath)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", cfg)
	srv := sshdtest.Start(t, bin, cfgPath, port)

	client := sshdtest.Dial(t, port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Start("sleep 30"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	var worker, sessionProc *procInfo
	for _, p := range listProcs(t) {
		if p.ppid != srv.PID {
			continue
		}
		switch {
		case strings.Contains(p.cmdline, "--internal-worker"):
			copied := p
			worker = &copied
		case p.uid == u.UID:
			copied := p
			sessionProc = &copied
		}
	}
	if worker == nil {
		t.Fatal("worker process not found")
	}
	if worker.uid == 0 {
		t.Fatal("worker is running as root")
	}
	if sessionProc == nil {
		t.Fatal("session process not found")
	}
	if sessionProc.uid != u.UID {
		t.Fatalf("session uid=%d want %d", sessionProc.uid, u.UID)
	}
}
