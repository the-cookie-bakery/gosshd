package privsep

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/auth"
	"github.com/cookiengineer/gosshd/internal/config"
)

type rpcResponse struct {
	result *Result
	fds    []int
	err    error
}

type rpcClient struct {
	pc      *PacketConn
	next    uint64
	mu      sync.Mutex
	pending map[uint64]chan rpcResponse
}

func newRPCClient(pc *PacketConn) *rpcClient {
	r := &rpcClient{pc: pc, pending: map[uint64]chan rpcResponse{}}
	go r.readLoop()
	return r
}

func (r *rpcClient) readLoop() {
	for {
		p, fds, err := r.pc.Read()
		if err != nil {
			log.Printf("rpc read: %v", err)
			r.mu.Lock()
			for _, ch := range r.pending {
				ch <- rpcResponse{err: err}
			}
			r.pending = map[uint64]chan rpcResponse{}
			r.mu.Unlock()
			return
		}
		if p.Type != "response" || p.Result == nil {
			continue
		}
		r.mu.Lock()
		ch, ok := r.pending[p.ID]
		delete(r.pending, p.ID)
		r.mu.Unlock()
		if ok {
			ch <- rpcResponse{result: p.Result, fds: fds}
		} else {
			for _, fd := range fds {
				syscall.Close(fd)
			}
		}
	}
}

func (r *rpcClient) call(p *Packet) (*Result, []int, error) {
	r.mu.Lock()
	r.next++
	p.ID = r.next
	ch := make(chan rpcResponse, 1)
	r.pending[p.ID] = ch
	r.mu.Unlock()
	if err := r.pc.Write(p); err != nil {
		return nil, nil, err
	}
	resp := <-ch
	return resp.result, resp.fds, resp.err
}

type remoteSigner struct {
	index int
	pub   ssh.PublicKey
	algos []string
	rpc   *rpcClient
}

func (s *remoteSigner) Algorithms() []string {
	if len(s.algos) == 0 {
		return []string{s.pub.Type()}
	}
	return append([]string(nil), s.algos...)
}

func (s *remoteSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

func (s *remoteSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

func (s *remoteSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	res, _, err := s.rpc.call(&Packet{Type: "sign", KeyIndex: s.index, Algo: algorithm, Data: data})
	if err != nil {
		return nil, err
	}
	if res == nil || !res.OK {
		if res != nil {
			return nil, errors.New(res.Error)
		}
		return nil, errors.New("signing failed")
	}
	return res.Signature, nil
}

func RunWorker() error {
	rawInit, err := base64.StdEncoding.DecodeString(os.Getenv("GOSSHD_WORKER_INIT"))
	if err != nil {
		return fmt.Errorf("decode worker init: %w", err)
	}
	var init WorkerInit
	if err := json.Unmarshal(rawInit, &init); err != nil {
		return fmt.Errorf("decode worker config: %w", err)
	}
	if init.Config == nil {
		return errors.New("missing worker config")
	}
	connFile := os.NewFile(3, "connection")
	if connFile == nil {
		return errors.New("missing connection fd")
	}
	ctrlFile := os.NewFile(4, "control")
	if ctrlFile == nil {
		return errors.New("missing control fd")
	}
	conn, err := net.FileConn(connFile)
	if err != nil {
		return fmt.Errorf("net.FileConn: %w", err)
	}
	connFile.Close()
	pc, err := NewPacketConn(ctrlFile)
	if err != nil {
		return fmt.Errorf("packet conn: %w", err)
	}
	ctrlFile.Close()
	rpc := newRPCClient(pc)
	cfg := init.Config
	var signers []ssh.Signer
	for i, hk := range init.HostKeys {
		pub, err := ssh.ParsePublicKey(hk.Blob)
		if err != nil {
			return err
		}
		signers = append(signers, &remoteSigner{index: i, pub: pub, algos: hk.Algorithms, rpc: rpc})
	}
	serverCfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges:   cfg.KexAlgorithms,
			Ciphers:        cfg.Ciphers,
			MACs:           cfg.MACs,
			RekeyThreshold: uint64(cfg.RekeyLimit),
		},
		MaxAuthTries:            cfg.MaxAuthTries,
		PublicKeyAuthAlgorithms: cfg.PubkeyAcceptedAlgorithms,
		ServerVersion:           "SSH-2.0-gosshd",
	}
	for _, s := range signers {
		serverCfg.AddHostKey(s)
	}
	auth := &authHandler{rpc: rpc, cfg: cfg}
	initialMethods := initialAuthMethods(cfg.AuthenticationMethods)
	if len(cfg.AuthenticationMethods) == 0 {
		initialMethods = []string{"publickey", "password", "keyboard-interactive"}
	}
	initialCallbacks := auth.callbacks(initialMethods)
	serverCfg.PasswordCallback = initialCallbacks.PasswordCallback
	serverCfg.PublicKeyCallback = initialCallbacks.PublicKeyCallback
	serverCfg.KeyboardInteractiveCallback = initialCallbacks.KeyboardInteractiveCallback
	serverCfg.VerifiedPublicKeyCallback = auth.verifiedCallback
	serverCfg.AuthLogCallback = func(conn ssh.ConnMetadata, method string, err error) {
		if err != nil {
			log.Printf("auth failed user=%q method=%s remote=%s", conn.User(), method, conn.RemoteAddr())
		}
	}
	if cfg.LoginGraceTime > 0 {
		_ = conn.SetDeadline(time.Now().Add(cfg.LoginGraceTime))
	}
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
	if err != nil {
		return fmt.Errorf("ssh handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	defer sshConn.Close()
	applyTCPKeepAlive(conn, cfg.TCPKeepAlive)

	var noMoreSessions atomic.Bool
	stopKeepalive := make(chan struct{})
	defer close(stopKeepalive)
	go handleGlobalRequests(reqs, &noMoreSessions)
	startClientAlive(sshConn, cfg.ClientAliveInterval, cfg.ClientAliveCountMax, stopKeepalive)

	for newChan := range chans {
		if noMoreSessions.Load() {
			newChan.Reject(ssh.Prohibited, "no more sessions")
			continue
		}
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go handleSession(sshConn, ch, requests, rpc, cfg)
	}
	return nil
}

func handleGlobalRequests(reqs <-chan *ssh.Request, noMoreSessions *atomic.Bool) {
	for req := range reqs {
		switch req.Type {
		case "keepalive@openssh.com":
			req.Reply(true, nil)
		case "no-more-sessions@openssh.com":
			noMoreSessions.Store(true)
			req.Reply(true, nil)
		case "tcpip-forward", "cancel-tcpip-forward",
			"streamlocal-forward@openssh.com", "cancel-streamlocal-forward@openssh.com":
			req.Reply(false, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func applyTCPKeepAlive(conn net.Conn, enabled bool) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(enabled)
	}
}

type authHandler struct {
	rpc *rpcClient
	cfg *config.Config
}

func (h *authHandler) callbacks(methods []string) ssh.ServerAuthCallbacks {
	var callbacks ssh.ServerAuthCallbacks
	for _, method := range methods {
		switch method {
		case "password":
			if h.cfg.PasswordAuthentication || len(h.cfg.Matches) > 0 {
				callbacks.PasswordCallback = h.passwordCallback
			}
		case "keyboard-interactive":
			if h.cfg.KbdInteractiveAuthentication || len(h.cfg.Matches) > 0 {
				callbacks.KeyboardInteractiveCallback = h.keyboardCallback
			}
		case "publickey":
			if h.cfg.PubkeyAuthentication || len(h.cfg.Matches) > 0 {
				callbacks.PublicKeyCallback = h.publicKeyQuery
			}
		}
	}
	return callbacks
}

func (h *authHandler) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	res, _, err := h.rpc.call(&Packet{Type: "password", User: conn.User(), Password: append([]byte(nil), password...), Remote: conn.RemoteAddr().String()})
	if err != nil {
		return nil, err
	}
	return h.result(res)
}

func (h *authHandler) keyboardCallback(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	ans, err := client("", "", []string{"Password: "}, []bool{false})
	if err != nil || len(ans) != 1 {
		return nil, errors.New("password required")
	}
	res, _, err := h.rpc.call(&Packet{Type: "keyboard", User: conn.User(), Password: []byte(ans[0]), Remote: conn.RemoteAddr().String()})
	if err != nil {
		return nil, err
	}
	return h.result(res)
}

func (h *authHandler) publicKeyQuery(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	res, _, err := h.rpc.call(&Packet{Type: "pubkey_authorize", User: conn.User(), Key: key.Marshal(), Remote: conn.RemoteAddr().String()})
	if err != nil {
		return nil, err
	}
	return resultPerms(res)
}

func (h *authHandler) verifiedCallback(conn ssh.ConnMetadata, key ssh.PublicKey, permissions *ssh.Permissions, signatureAlgorithm string) (*ssh.Permissions, error) {
	res, _, err := h.rpc.call(&Packet{Type: "pubkey_verified", User: conn.User(), Key: key.Marshal(), Algo: signatureAlgorithm, Remote: conn.RemoteAddr().String()})
	if err != nil {
		return nil, err
	}
	return h.result(res)
}

func (h *authHandler) result(res *Result) (*ssh.Permissions, error) {
	if res == nil {
		return nil, errors.New("empty auth response")
	}
	if res.Partial {
		return nil, &ssh.PartialSuccessError{Next: h.callbacks(res.NextMethods)}
	}
	if !res.OK || res.Permissions == nil {
		if res.Error == "" {
			return nil, auth.ErrAccessDenied
		}
		return nil, errors.New(res.Error)
	}
	return resultPerms(res)
}

func resultPerms(res *Result) (*ssh.Permissions, error) {
	if res == nil {
		return nil, errors.New("empty auth response")
	}
	if !res.OK || res.Permissions == nil {
		if res.Error == "" {
			return nil, auth.ErrAccessDenied
		}
		return nil, errors.New(res.Error)
	}
	p := res.Permissions
	sp := &ssh.Permissions{
		CriticalOptions: map[string]string{},
		Extensions:      map[string]string{},
		ExtraData:       map[any]any{"gosshd": p},
	}
	if p.SourceAddress != "" {
		sp.CriticalOptions["source-address"] = p.SourceAddress
	}
	return sp, nil
}

type ptyRequest struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  string
}

type envRequest struct {
	Name  string
	Value string
}

type execRequest struct {
	Command string
}

type subsystemRequest struct {
	Subsystem string
}

type windowChange struct {
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
}

type signalRequest struct {
	Signal string
}

type sessionHandler struct {
	conn      *ssh.ServerConn
	ch        ssh.Channel
	rpc       *rpcClient
	cfg       *config.Config
	perms     *auth.Permissions
	sessionID string
	started   bool
	pty       bool
	term      string
	cols      uint32
	rows      uint32
	modes     string
	env       []string
	mu        sync.Mutex
}

func handleSession(conn *ssh.ServerConn, ch ssh.Channel, requests <-chan *ssh.Request, rpc *rpcClient, cfg *config.Config) {
	log.Printf("session opened user=%q", conn.User())
	h := &sessionHandler{conn: conn, ch: ch, rpc: rpc, cfg: cfg}
	if p, ok := conn.Permissions.ExtraData["gosshd"].(*auth.Permissions); ok {
		h.perms = p
	}
	defer func() {
		if h.sessionID != "" {
			_, _, _ = h.rpc.call(&Packet{Type: "session_close", SessionID: h.sessionID})
		}
		ch.Close()
	}()
	for req := range requests {
		switch req.Type {
		case "pty-req":
			if h.perms == nil || h.perms.NoPTY || !cfg.PermitTTY {
				req.Reply(false, nil)
				continue
			}
			var r ptyRequest
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			h.pty = true
			h.term = r.Term
			h.cols = r.Cols
			h.rows = r.Rows
			h.modes = r.Modes
			h.mu.Unlock()
			req.Reply(true, nil)
		case "env":
			var r envRequest
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			h.env = append(h.env, r.Name+"="+r.Value)
			h.mu.Unlock()
			req.Reply(true, nil)
		case "shell":
			if h.started {
				req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			h.started = true
			h.mu.Unlock()
			relay, err := h.start("", "")
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			relay()
		case "exec":
			if h.started {
				req.Reply(false, nil)
				continue
			}
			var r execRequest
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			h.started = true
			h.mu.Unlock()
			relay, err := h.start(r.Command, "")
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			relay()
		case "subsystem":
			if h.started {
				req.Reply(false, nil)
				continue
			}
			var r subsystemRequest
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			h.started = true
			h.mu.Unlock()
			relay, err := h.start("", r.Subsystem)
			if err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			relay()
		case "window-change":
			var r windowChange
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			h.cols, h.rows = r.Cols, r.Rows
			id := h.sessionID
			h.mu.Unlock()
			if id != "" {
				_, _, _ = h.rpc.call(&Packet{Type: "session_resize", SessionID: id, Width: r.Cols, Height: r.Rows})
			}
			req.Reply(true, nil)
		case "signal":
			var r signalRequest
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			id := h.sessionID
			h.mu.Unlock()
			if id != "" {
				_, _, _ = h.rpc.call(&Packet{Type: "session_signal", SessionID: id, Signal: int(signalNumber(r.Signal))})
			}
			req.Reply(true, nil)
		case "break":
			req.Reply(true, nil)
		case "x11-req", "auth-agent-req@openssh.com":
			req.Reply(false, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func (h *sessionHandler) start(command, subsystem string) (func(), error) {
	log.Printf("session start command=%q subsystem=%q", command, subsystem)
	h.mu.Lock()
	pty := h.pty
	term := h.term
	cols, rows := h.cols, h.rows
	modes := h.modes
	env := append([]string(nil), h.env...)
	h.mu.Unlock()
	res, fds, err := h.rpc.call(&Packet{
		Type: "session_open", User: h.conn.User(), Pty: pty, Term: term,
		Width: cols, Height: rows, Command: command, Subsystem: subsystem,
		Env: env, Remote: h.conn.RemoteAddr().String(), Modes: modes,
	})
	if err != nil {
		return nil, err
	}
	if res == nil || !res.OK {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		if res != nil {
			return nil, errors.New(res.Error)
		}
		return nil, errors.New("session open failed")
	}
	log.Printf("session opened id=%s", res.SessionID)
	h.mu.Lock()
	h.sessionID = res.SessionID
	h.mu.Unlock()
	if pty {
		if len(fds) != 1 {
			for _, fd := range fds {
				syscall.Close(fd)
			}
			return nil, errors.New("session fd missing")
		}
		f := os.NewFile(uintptr(fds[0]), "session")
		if f == nil {
			return nil, errors.New("invalid session fd")
		}
		return func() { go h.relayPty(f) }, nil
	}
	if len(fds) != 2 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, errors.New("session fds missing")
	}
	in := os.NewFile(uintptr(fds[0]), "session-stdin")
	out := os.NewFile(uintptr(fds[1]), "session-stdout")
	if in == nil || out == nil {
		closeLocalFiles(in, out)
		return nil, errors.New("invalid session fds")
	}
	return func() { go h.relaySock(in, out) }, nil
}

func closeLocalFiles(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			f.Close()
		}
	}
}

func (h *sessionHandler) relayPty(f *os.File) {
	log.Printf("session pty relay start")
	defer f.Close()
	h.mu.Lock()
	id := h.sessionID
	h.mu.Unlock()
	if id == "" {
		return
	}
	resCh := make(chan *Result, 1)
	go func() {
		res, _, err := h.rpc.call(&Packet{Type: "session_wait", SessionID: id})
		if err != nil || res == nil {
			resCh <- nil
			return
		}
		resCh <- res
	}()
	go func() {
		_, _ = io.Copy(f, h.ch)
	}()
	_, _ = io.Copy(h.ch, f)
	res := <-resCh
	if res == nil {
		log.Printf("session wait failed")
		return
	}
	log.Printf("session exit status=%d signal=%q", res.ExitStatus, res.Signal)
	h.sendExit(res)
}

func (h *sessionHandler) relaySock(in, out *os.File) {
	log.Printf("session socket relay start")
	defer closeLocalFiles(in, out)
	h.mu.Lock()
	id := h.sessionID
	h.mu.Unlock()
	if id == "" {
		return
	}
	resCh := make(chan *Result, 1)
	go func() {
		res, _, err := h.rpc.call(&Packet{Type: "session_wait", SessionID: id})
		if err != nil || res == nil {
			resCh <- nil
			return
		}
		resCh <- res
	}()
	go func() {
		_, _ = io.Copy(in, h.ch)
		_ = in.Close()
	}()
	n, err := io.Copy(h.ch, out)
	log.Printf("session output copied %d bytes err=%v", n, err)
	res := <-resCh
	if res == nil {
		log.Printf("session wait failed")
		return
	}
	log.Printf("session exit status=%d signal=%q", res.ExitStatus, res.Signal)
	h.sendExit(res)
}

func (h *sessionHandler) sendExit(res *Result) {
	if res.Signal != "" {
		payload := ssh.Marshal(struct {
			Signal       string
			CoreDumped   bool
			ErrorMessage string
			Language     string
		}{Signal: res.Signal})
		_, _ = h.ch.SendRequest("exit-signal", false, payload)
	} else {
		payload := ssh.Marshal(struct{ Status uint32 }{Status: uint32(res.ExitStatus)})
		_, _ = h.ch.SendRequest("exit-status", false, payload)
	}
	_ = h.ch.CloseWrite()
	_ = h.ch.Close()
}

func signalNumber(name string) syscall.Signal {
	switch name {
	case "ABRT":
		return syscall.SIGABRT
	case "ALRM":
		return syscall.SIGALRM
	case "FPE":
		return syscall.SIGFPE
	case "HUP":
		return syscall.SIGHUP
	case "ILL":
		return syscall.SIGILL
	case "INT":
		return syscall.SIGINT
	case "KILL":
		return syscall.SIGKILL
	case "PIPE":
		return syscall.SIGPIPE
	case "QUIT":
		return syscall.SIGQUIT
	case "SEGV":
		return syscall.SIGSEGV
	case "TERM":
		return syscall.SIGTERM
	case "USR1":
		return syscall.SIGUSR1
	case "USR2":
		return syscall.SIGUSR2
	default:
		return syscall.SIGTERM
	}
}
