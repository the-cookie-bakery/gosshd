//go:build e2e

package privsep

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/cookiengineer/gosshd/e2e-tests/suites/internal/sshdtest"
)

type procInfo struct {
	pid     int
	ppid    int
	uid     int
	gid     int
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
		info := procInfo{pid: pid, ppid: -1, uid: -1, gid: -1}
		for _, line := range strings.Split(string(status), "\n") {
			switch {
			case strings.HasPrefix(line, "PPid:"):
				fmt.Sscanf(line, "PPid:\t%d", &info.ppid)
			case strings.HasPrefix(line, "Uid:"):
				fields := strings.Fields(line)
				if len(fields) > 1 {
					info.uid, _ = strconv.Atoi(fields[1])
				}
			case strings.HasPrefix(line, "Gid:"):
				fields := strings.Fields(line)
				if len(fields) > 1 {
					info.gid, _ = strconv.Atoi(fields[1])
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

	assertMonitorCapabilities(t, srv.PID)
	assertWorkerNoCapabilities(t, worker.pid)
	assertUnprivilegedAccessDenied(t, worker, hostPath)
}

func readStatusCaps(path string) (uint64, uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var eff, bnd uint64
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "CapEff:":
			eff = n
		case "CapBnd:":
			bnd = n
		}
	}
	return eff, bnd, nil
}

func capSet(mask uint64, cap int) bool {
	return mask&(1<<uint(cap)) != 0
}

func assertMonitorCapabilities(t *testing.T, pid int) {
	t.Helper()
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatal(err)
	}
	wantEff, wantBnd, err := readStatusCaps(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		eff, bnd, err := readStatusCaps(fmt.Sprintf("/proc/%d/task/%s/status", pid, task.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if eff != wantEff || bnd != wantBnd {
			t.Fatalf("thread %s caps differ: eff=%#x/%#x bnd=%#x/%#x", task.Name(), eff, wantEff, bnd, wantBnd)
		}
	}
	for _, cap := range []int{unix.CAP_SYS_ADMIN, unix.CAP_SYS_PTRACE, unix.CAP_NET_RAW, unix.CAP_NET_ADMIN, unix.CAP_SYS_MODULE, unix.CAP_BPF} {
		if capSet(wantEff, cap) {
			t.Fatalf("monitor retains CAP_%d in effective set", cap)
		}
		if capSet(wantBnd, cap) {
			t.Fatalf("monitor retains CAP_%d in bounding set", cap)
		}
	}
	for _, cap := range []int{unix.CAP_DAC_OVERRIDE, unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_SYS_CHROOT} {
		if !capSet(wantBnd, cap) {
			t.Fatalf("monitor bounding set is missing CAP_%d", cap)
		}
	}
	for _, cap := range []int{unix.CAP_DAC_OVERRIDE, unix.CAP_KILL, unix.CAP_SETUID, unix.CAP_SETGID} {
		if !capSet(wantEff, cap) {
			t.Fatalf("monitor effective set is missing CAP_%d", cap)
		}
	}
}

func assertWorkerNoCapabilities(t *testing.T, pid int) {
	t.Helper()
	eff, _, err := readStatusCaps(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	if eff != 0 {
		t.Fatalf("worker CapEff=%#x want 0", eff)
	}
}

func assertUnprivilegedAccessDenied(t *testing.T, worker *procInfo, hostKeyPath string) {
	t.Helper()
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Log("setpriv not available; skipping access-denial assertions")
		return
	}
	for _, path := range []string{"/etc/shadow", hostKeyPath} {
		cmd := exec.Command("setpriv",
			"--reuid", strconv.Itoa(worker.uid),
			"--regid", strconv.Itoa(worker.gid),
			"--clear-groups",
			"cat", path,
		)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("unprivileged uid could read %s: %s", path, out)
		}
	}
}

func TestDisconnectCleanup(t *testing.T) {
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
`, port, hostPath)
	cfgPath := sshdtest.WriteFile(t, dir, "sshd_config", cfg)
	sshdtest.Start(t, bin, cfgPath, port)

	client := sshdtest.Dial(t, port, sshdtest.ClientConfig(u.Name, ssh.PublicKeys(signer)))
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("sleep 987654"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	marker := "sleep 987654"
	if !processExistsWithCmdline(t, marker) {
		t.Fatal("session process not found before disconnect")
	}
	client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !processExistsWithCmdline(t, marker) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("session process survived client disconnect")
}

func processExistsWithCmdline(t *testing.T, marker string) bool {
	t.Helper()
	for _, p := range listProcs(t) {
		if strings.Contains(p.cmdline, marker) {
			return true
		}
	}
	return false
}
