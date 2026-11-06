package privsep

import (
	"bytes"
	"encoding/gob"
	"errors"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/cookiengineer/gosshd/internal/auth"
)

const maxPacket = 2 << 20

type Result struct {
	OK          bool
	Error       string
	Permissions *auth.Permissions
	Signature   *ssh.Signature
	SessionID   string
	ExitStatus  int
	Signal      string
	Partial     bool
	NextMethods []string
}

type Packet struct {
	ID        uint64
	Type      string
	KeyIndex  int
	User      string
	Password  []byte
	Key       []byte
	Algo      string
	Data      []byte
	Signature *ssh.Signature
	Result    *Result
	SessionID string
	Pty       bool
	Term      string
	Width     uint32
	Height    uint32
	Command   string
	Subsystem string
	Signal    int
	Env       []string
	Remote    string
	Local     string
	Modes     string
}

type PacketConn struct {
	conn *net.UnixConn
	mu   sync.Mutex
}

func NewPacketConn(f *os.File) (*PacketConn, error) {
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("not a unix socket")
	}
	return &PacketConn{conn: uc}, nil
}

func NewPacketConnFromNet(c net.Conn) (*PacketConn, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket")
	}
	return &PacketConn{conn: uc}, nil
}

func (c *PacketConn) Close() error {
	return c.conn.Close()
}

func (c *PacketConn) Write(p *Packet, fds ...int) error {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(p); err != nil {
		return err
	}
	if b.Len() > maxPacket {
		return errors.New("packet too large")
	}
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _, err := c.conn.WriteMsgUnix(b.Bytes(), oob, nil)
	return err
}

func decodePacket(data []byte) (*Packet, error) {
	p := &Packet{}
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(p); err != nil {
		return nil, err
	}
	return p, nil
}

func (c *PacketConn) Read() (*Packet, []int, error) {
	buf := make([]byte, maxPacket)
	oob := make([]byte, 4096)
	n, oobn, _, _, err := c.conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, nil, err
	}
	p, err := decodePacket(buf[:n])
	if err != nil {
		return nil, nil, err
	}
	fds, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return p, nil, nil
	}
	var out []int
	for _, m := range fds {
		rights, err := unix.ParseUnixRights(&m)
		if err == nil {
			out = append(out, rights...)
		}
	}
	return p, out, nil
}
