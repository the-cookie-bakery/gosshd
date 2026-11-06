package privsep

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/cookiengineer/gosshd/internal/auth"
	"github.com/cookiengineer/gosshd/internal/config"
	"github.com/cookiengineer/gosshd/internal/nss"
)

type HostKeyPublic struct {
	Blob []byte
}

type WorkerInit struct {
	Config   *config.Config
	HostKeys []HostKeyPublic
}

type SessionSpec struct {
	UID              uint32
	GID              uint32
	Groups           []uint32
	Home             string
	Shell            string
	Command          string
	Subsystem        string
	SubsystemCommand string
	Chroot           string
	Env              []string
	Remote           string
	NoUserRC         bool
	Pty              bool
}

type session struct {
	id          string
	cmd         *exec.Cmd
	master      *os.File
	workerFiles []*os.File
	pty         bool
	done        chan struct{}
	mu          sync.Mutex
	exit        int
	signal      string
	waitErr     error
	counted     bool
}

func (s *session) closeMaster() {
	s.mu.Lock()
	m := s.master
	s.master = nil
	s.mu.Unlock()
	if m != nil {
		m.Close()
	}
}

type sessionState struct {
	perms    *auth.Permissions
	sessions map[string]*session
	closed   bool
	mu       sync.Mutex
}

func newSessionState() *sessionState {
	return &sessionState{sessions: map[string]*session{}}
}

func (st *sessionState) setPerms(p *auth.Permissions) {
	st.mu.Lock()
	st.perms = p
	st.mu.Unlock()
}

func (st *sessionState) getPerms() *auth.Permissions {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.perms
}

func (st *sessionState) getSession(id string) *session {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sessions[id]
}

func (st *sessionState) addSessionIfRoom(s *session, max int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return errors.New("connection is closing")
	}
	if len(st.sessions) >= max {
		return errors.New("too many sessions")
	}
	st.sessions[s.id] = s
	return nil
}

func (st *sessionState) removeSession(id string) *session {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.sessions[id]
	delete(st.sessions, id)
	return s
}

func (st *sessionState) takeAll() []*session {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.closed = true
	out := make([]*session, 0, len(st.sessions))
	for _, s := range st.sessions {
		out = append(out, s)
	}
	st.sessions = map[string]*session{}
	return out
}

type Monitor struct {
	cfg       *config.Config
	auth      *auth.Authenticator
	signers   []ssh.Signer
	workerUID uint32
	workerGID uint32
	drop      bool
	startups  chan struct{}
	listeners []net.Listener
	wg        sync.WaitGroup
}

func NewMonitor(cfg *config.Config, a *auth.Authenticator, signers []ssh.Signer) *Monitor {
	m := &Monitor{cfg: cfg, auth: a, signers: signers, startups: make(chan struct{}, maxInt(cfg.MaxStartups, 1))}
	if os.Geteuid() == 0 {
		if u, err := nss.LookupUser("nobody"); err == nil {
			m.workerUID = u.UID
			m.workerGID = u.GID
			m.drop = true
		} else {
			m.workerUID = 65534
			m.workerGID = 65534
			m.drop = true
		}
	}
	return m
}

func (m *Monitor) Listen() error {
	addrs, err := m.cfg.Listeners()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			m.Close()
			return err
		}
		m.listeners = append(m.listeners, ln)
	}
	return nil
}

func (m *Monitor) Addrs() []net.Addr {
	var out []net.Addr
	for _, l := range m.listeners {
		out = append(out, l.Addr())
	}
	return out
}

func (m *Monitor) Serve(ctx context.Context) error {
	for _, ln := range m.listeners {
		m.wg.Add(1)
		go func(l net.Listener) {
			defer m.wg.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				select {
				case m.startups <- struct{}{}:
					go func() {
						defer func() { <-m.startups }()
						m.handleConn(conn)
					}()
				default:
					conn.Close()
				}
			}
		}(ln)
	}
	<-ctx.Done()
	return m.Close()
}

func (m *Monitor) Close() error {
	for _, l := range m.listeners {
		l.Close()
	}
	m.wg.Wait()
	return nil
}

func (m *Monitor) handleConn(conn net.Conn) {
	mon, worker, err := unixSocketpair()
	if err != nil {
		conn.Close()
		return
	}
	defer mon.Close()
	defer worker.Close()
	tcpFile, err := connFile(conn)
	if err != nil {
		conn.Close()
		return
	}
	defer tcpFile.Close()
	conn.Close()

	initData := WorkerInit{Config: m.cfg.Clone()}
	for _, s := range m.signers {
		initData.HostKeys = append(initData.HostKeys, HostKeyPublic{Blob: s.PublicKey().Marshal()})
	}
	raw, err := json.Marshal(initData)
	if err != nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "--internal-worker")
	cmd.Env = []string{
		"GOSSHD_WORKER_INIT=" + base64.StdEncoding.EncodeToString(raw),
		"PATH=/usr/bin:/bin",
	}
	cmd.ExtraFiles = []*os.File{tcpFile, worker}
	cmd.Stdin = nil
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if m.drop {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: m.workerUID, Gid: m.workerGID}}
	}
	if err := cmd.Start(); err != nil {
		return
	}
	worker.Close()
	tcpFile.Close()
	pc, err := NewPacketConn(mon)
	if err != nil {
		cmd.Process.Kill()
		return
	}
	defer pc.Close()
	st := newSessionState()
	var handlers sync.WaitGroup
	for {
		pkt, fds, err := pc.Read()
		for _, fd := range fds {
			unix.Close(fd)
		}
		if err != nil {
			log.Printf("control read: %v", err)
			break
		}
		handlers.Add(1)
		go func(pkt *Packet) {
			defer handlers.Done()
			m.handleAndRespond(st, pc, pkt)
		}(pkt)
	}
	shutdownSessions(st)
	pc.Close()
	handlers.Wait()
	shutdownSessions(st)
	cmd.Wait()
}

func (m *Monitor) handleAndRespond(st *sessionState, pc *PacketConn, pkt *Packet) {
	res := m.handlePacket(st, pkt)
	var sendFDs []int
	var closeAfter []*os.File
	if res != nil && res.OK && pkt.Type == "session_open" {
		if s := st.getSession(res.SessionID); s != nil {
			s.mu.Lock()
			files := s.workerFiles
			if !s.pty {
				s.workerFiles = nil
			}
			s.mu.Unlock()
			for _, f := range files {
				sendFDs = append(sendFDs, int(f.Fd()))
			}
			if !s.pty {
				closeAfter = files
			}
		}
	}
	resp := &Packet{ID: pkt.ID, Type: "response", Result: res}
	if err := pc.Write(resp, sendFDs...); err != nil {
		closeFiles(closeAfter...)
		log.Printf("control write: %v", err)
		return
	}
	closeFiles(closeAfter...)
}

func shutdownSessions(st *sessionState) {
	for _, s := range st.takeAll() {
		if s.cmd.Process != nil {
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
			_ = s.cmd.Process.Kill()
		}
		s.closeMaster()
	}
}

func (m *Monitor) handlePacket(st *sessionState, p *Packet) *Result {
	switch p.Type {
	case "sign":
		if p.KeyIndex < 0 || p.KeyIndex >= len(m.signers) {
			return &Result{Error: "invalid host key index"}
		}
		signer := m.signers[p.KeyIndex]
		var sig *ssh.Signature
		var err error
		if as, ok := signer.(ssh.AlgorithmSigner); ok && p.Algo != "" {
			sig, err = as.SignWithAlgorithm(rand.Reader, p.Data, p.Algo)
		} else {
			sig, err = signer.Sign(rand.Reader, p.Data)
		}
		if err != nil {
			return &Result{Error: err.Error()}
		}
		return &Result{OK: true, Signature: sig}
	case "password", "keyboard":
		if p.Type == "password" && !m.cfg.PasswordAuthentication {
			return &Result{Error: "password authentication disabled"}
		}
		if p.Type == "keyboard" && !m.cfg.KbdInteractiveAuthentication {
			return &Result{Error: "keyboard-interactive authentication disabled"}
		}
		perms, err := m.auth.Password(p.User, p.Password, remoteFromString(p.Remote))
		for i := range p.Password {
			p.Password[i] = 0
		}
		if err != nil {
			return &Result{Error: err.Error()}
		}
		st.setPerms(perms)
		return &Result{OK: true, Permissions: perms}
	case "pubkey_authorize":
		if !m.cfg.PubkeyAuthentication {
			return &Result{Error: "public key authentication disabled"}
		}
		key, err := ssh.ParsePublicKey(p.Key)
		if err != nil {
			return &Result{Error: "invalid public key"}
		}
		perms, err := m.auth.PublicKey(p.User, key, remoteFromString(p.Remote))
		if err != nil {
			return &Result{Error: err.Error()}
		}
		st.setPerms(perms)
		return &Result{OK: true, Permissions: perms}
	case "session_open":
		perms := st.getPerms()
		if perms == nil {
			return &Result{Error: "not authenticated"}
		}
		id, err := m.openSession(st, perms, p)
		if err != nil {
			return &Result{Error: err.Error()}
		}
		return &Result{OK: true, SessionID: id}
	case "session_resize":
		s := st.getSession(p.SessionID)
		if s == nil || !s.pty {
			return &Result{Error: "unknown session"}
		}
		s.mu.Lock()
		master := s.master
		s.mu.Unlock()
		if master == nil {
			return &Result{Error: "unknown session"}
		}
		if err := pty.Setsize(master, &pty.Winsize{Cols: uint16(p.Width), Rows: uint16(p.Height)}); err != nil {
			return &Result{Error: err.Error()}
		}
		return &Result{OK: true}
	case "session_signal":
		s := st.getSession(p.SessionID)
		if s == nil || s.cmd.Process == nil {
			return &Result{Error: "unknown session"}
		}
		sig := syscall.Signal(p.Signal)
		if err := syscall.Kill(-s.cmd.Process.Pid, sig); err != nil {
			_ = s.cmd.Process.Signal(sig)
		}
		return &Result{OK: true}
	case "session_wait":
		s := st.getSession(p.SessionID)
		if s == nil {
			return &Result{Error: "unknown session"}
		}
		<-s.done
		s.mu.Lock()
		exit, sig, waitErr := s.exit, s.signal, s.waitErr
		s.mu.Unlock()
		if waitErr != nil {
			log.Printf("monitor session wait id=%s err=%v", p.SessionID, waitErr)
		}
		log.Printf("monitor session wait id=%s exit=%d signal=%q", p.SessionID, exit, sig)
		res := &Result{OK: true, ExitStatus: exit, Signal: sig}
		st.removeSession(p.SessionID)
		s.closeMaster()
		return res
	case "session_close":
		s := st.removeSession(p.SessionID)
		if s == nil {
			return &Result{OK: true}
		}
		if s.cmd.Process != nil {
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
			_ = s.cmd.Process.Kill()
		}
		s.closeMaster()
		return &Result{OK: true}
	default:
		return &Result{Error: "unknown request"}
	}
}

func (m *Monitor) openSession(st *sessionState, perms *auth.Permissions, p *Packet) (string, error) {
	log.Printf("monitor open session user=%q pty=%v command=%q subsystem=%q", perms.Username, p.Pty, p.Command, p.Subsystem)
	if p.Pty && (!m.cfg.PermitTTY || perms.NoPTY) {
		return "", errors.New("pty not permitted")
	}
	command := p.Command
	subsystem := p.Subsystem
	if m.cfg.ForceCommand != "" {
		command = m.cfg.ForceCommand
		subsystem = ""
	} else if perms.ForceCommand != "" {
		command = perms.ForceCommand
		subsystem = ""
	}
	if subsystem != "" {
		if _, ok := m.cfg.Subsystems[subsystem]; !ok {
			return "", errors.New("unknown subsystem")
		}
	}
	env := m.buildEnv(p.Env, perms)
	spec := SessionSpec{
		UID: perms.UID, GID: perms.GID, Groups: nil,
		Home: perms.Home, Shell: perms.Shell,
		Command: command, Subsystem: subsystem, SubsystemCommand: m.cfg.Subsystems[subsystem],
		Chroot: m.cfg.ChrootDirectory, Env: env,
		Remote: p.Remote, NoUserRC: perms.NoUserRC || !m.cfg.PermitUserRC,
		Pty: p.Pty,
	}
	for _, g := range perms.Groups {
		if gu, err := nss.LookupGroup(g); err == nil {
			spec.Groups = append(spec.Groups, gu.GID)
		}
	}
	var master *os.File
	var workerFiles []*os.File
	var childIn, childOut, childErr *os.File
	isPty := p.Pty
	if isPty {
		mf, sf, err := pty.Open()
		if err != nil {
			return "", err
		}
		master = mf
		workerFiles = []*os.File{mf}
		childIn, childOut, childErr = sf, sf, sf
		if p.Width > 0 && p.Height > 0 {
			_ = pty.Setsize(mf, &pty.Winsize{Cols: uint16(p.Width), Rows: uint16(p.Height)})
		}
	} else {
		inFds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return "", err
		}
		outFds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			unix.Close(inFds[0])
			unix.Close(inFds[1])
			return "", err
		}
		childIn = os.NewFile(uintptr(inFds[1]), "session-stdin")
		childOut = os.NewFile(uintptr(outFds[0]), "session-stdout")
		childErr = childOut
		workerFiles = []*os.File{
			os.NewFile(uintptr(inFds[0]), "session-stdin-worker"),
			os.NewFile(uintptr(outFds[1]), "session-stdout-worker"),
		}
	}
	rawSpec, err := json.Marshal(spec)
	if err != nil {
		closeFiles(workerFiles...)
		closeFiles(childIn, childOut, childErr)
		return "", err
	}
	exe, err := os.Executable()
	if err != nil {
		closeFiles(workerFiles...)
		closeFiles(childIn, childOut, childErr)
		return "", err
	}
	cmd := exec.Command(exe, "--internal-session")
	cmd.Env = []string{"GOSSHD_SESSION_SPEC=" + base64.StdEncoding.EncodeToString(rawSpec), "PATH=/usr/bin:/bin"}
	cmd.Stdin = childIn
	cmd.Stdout = childOut
	cmd.Stderr = childErr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if isPty {
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = 0
	}
	if err := cmd.Start(); err != nil {
		closeFiles(workerFiles...)
		closeFiles(childIn, childOut, childErr)
		return "", err
	}
	closeFiles(childIn, childOut, childErr)
	id := sessionID()
	s := &session{id: id, cmd: cmd, master: master, workerFiles: workerFiles, pty: isPty, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				s.exit = ee.ExitCode()
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					s.signal = ws.Signal().String()
				}
			} else {
				s.waitErr = err
			}
		}
		s.mu.Unlock()
		close(s.done)
	}()
	if err := st.addSessionIfRoom(s, m.cfg.MaxSessions); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		closeFiles(workerFiles...)
		return "", err
	}
	log.Printf("monitor session started id=%s pid=%d", id, cmd.Process.Pid)
	return id, nil
}

func closeFiles(files ...*os.File) {
	seen := map[*os.File]bool{}
	for _, f := range files {
		if f == nil || seen[f] {
			continue
		}
		seen[f] = true
		f.Close()
	}
}

func (m *Monitor) buildEnv(clientEnv []string, perms *auth.Permissions) []string {
	env := []string{
		"HOME=" + perms.Home,
		"USER=" + perms.Username,
		"LOGNAME=" + perms.Username,
		"SHELL=" + perms.Shell,
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	for k, v := range m.cfg.SetEnv {
		env = append(env, k+"="+v)
	}
	for _, kv := range perms.Environment {
		if strings.Contains(kv, "=") && m.cfg.PermitUserEnvironment == "yes" {
			env = append(env, kv)
		}
	}
	for _, kv := range clientEnv {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || strings.ContainsAny(k, "\x00=") {
			continue
		}
		if k == "TERM" || matchAny(m.cfg.AcceptEnv, k) {
			env = append(env, kv)
		}
	}
	return dedupeEnv(env)
}

func matchAny(patterns []string, key string) bool {
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, key); ok {
			return true
		}
	}
	return false
}

func dedupeEnv(env []string) []string {
	seen := map[string]int{}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := seen[k]; ok {
			out[i] = kv
			continue
		}
		seen[k] = len(out)
		out = append(out, kv)
	}
	return out
}

func remoteFromString(s string) net.Addr {
	if s == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return &net.TCPAddr{IP: net.ParseIP(s)}
	}
	port, _ := strconv.Atoi(portStr)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
}

func sessionID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func unixSocketpair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "monitor"), os.NewFile(uintptr(fds[1]), "worker"), nil
}

func connFile(c net.Conn) (*os.File, error) {
	type filer interface{ File() (*os.File, error) }
	if f, ok := c.(filer); ok {
		return f.File()
	}
	return nil, fmt.Errorf("cannot duplicate connection")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
