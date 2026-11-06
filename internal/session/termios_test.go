package session

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestApplyTerminalMode(t *testing.T) {
	var term unix.Termios
	term.Lflag = unix.ECHO | unix.ICANON
	term.Iflag = unix.IXON
	applyTerminalMode(&term, 53, 0)
	if term.Lflag&unix.ECHO != 0 {
		t.Fatal("ECHO was not cleared")
	}
	applyTerminalMode(&term, 40, 0)
	if term.Iflag&unix.IXON != 0 {
		t.Fatal("IXON was not cleared")
	}
	applyTerminalMode(&term, 1, 3)
	if term.Cc[unix.VINTR] != 3 {
		t.Fatalf("VINTR=%d", term.Cc[unix.VINTR])
	}
	applyTerminalMode(&term, 91, 1)
	if term.Cflag&unix.CSIZE != unix.CS8 {
		t.Fatalf("Cflag=%#x", term.Cflag)
	}
	applyTerminalMode(&term, 92, 1)
	if term.Cflag&unix.PARENB == 0 {
		t.Fatal("PARENB was not set")
	}
	applyTerminalMode(&term, 128, 9600)
	if term.Ispeed != 9600 {
		t.Fatalf("Ispeed=%d", term.Ispeed)
	}
}
