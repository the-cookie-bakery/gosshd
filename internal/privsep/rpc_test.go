package privsep

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func newTestPacketConns(t *testing.T) (*PacketConn, *PacketConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewPacketConn(os.NewFile(uintptr(fds[0]), "a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPacketConn(os.NewFile(uintptr(fds[1]), "b"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}

func TestPacketConnRoundTrip(t *testing.T) {
	a, b := newTestPacketConns(t)
	sent := &Packet{
		ID:       7,
		Type:     "password",
		User:     "alice",
		Password: []byte("secret"),
		Remote:   "192.0.2.10:2222",
	}
	if err := a.Write(sent); err != nil {
		t.Fatal(err)
	}
	got, fds, err := b.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(fds) != 0 {
		t.Fatalf("unexpected fds: %v", fds)
	}
	if got.ID != sent.ID || got.Type != sent.Type || got.User != sent.User || !bytes.Equal(got.Password, sent.Password) {
		t.Fatalf("packet mismatch: got %+v want %+v", got, sent)
	}
}

func TestPacketConnRejectsOversizedPacket(t *testing.T) {
	a, _ := newTestPacketConns(t)
	if err := a.Write(&Packet{Type: "sign", Data: make([]byte, maxPacket)}); err == nil {
		t.Fatal("expected oversized packet rejection")
	}
}

func TestPacketConnPassesFileDescriptors(t *testing.T) {
	a, b := newTestPacketConns(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := a.Write(&Packet{Type: "session_open"}, int(r.Fd())); err != nil {
		t.Fatal(err)
	}
	pkt, fds, err := b.Read()
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != "session_open" || len(fds) != 1 {
		t.Fatalf("got type=%q fds=%v", pkt.Type, fds)
	}
	received := os.NewFile(uintptr(fds[0]), "received")
	defer received.Close()
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	n, err := received.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("read %q", buf[:n])
	}
}
