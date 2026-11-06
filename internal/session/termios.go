package session

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

func applyTerminalModes(fd int, modes string) error {
	if modes == "" {
		return nil
	}
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	for i := 0; i < len(modes); {
		opcode := modes[i]
		i++
		if opcode == 0 {
			break
		}
		if opcode >= 160 {
			continue
		}
		if i+4 > len(modes) {
			return fmt.Errorf("truncated terminal mode %d", opcode)
		}
		value := binary.BigEndian.Uint32([]byte(modes[i : i+4]))
		i += 4
		applyTerminalMode(termios, opcode, value)
	}
	return unix.IoctlSetTermios(fd, unix.TCSETS, termios)
}

func applyTerminalMode(termios *unix.Termios, opcode byte, value uint32) {
	on := value != 0
	setFlag := func(flag *uint32, bit uint32) {
		if on {
			*flag |= bit
		} else {
			*flag &^= bit
		}
	}
	switch opcode {
	case 1:
		termios.Cc[unix.VINTR] = uint8(value)
	case 2:
		termios.Cc[unix.VQUIT] = uint8(value)
	case 3:
		termios.Cc[unix.VERASE] = uint8(value)
	case 4:
		termios.Cc[unix.VKILL] = uint8(value)
	case 5:
		termios.Cc[unix.VEOF] = uint8(value)
	case 6:
		termios.Cc[unix.VEOL] = uint8(value)
	case 7:
		termios.Cc[unix.VEOL2] = uint8(value)
	case 8:
		termios.Cc[unix.VSTART] = uint8(value)
	case 9:
		termios.Cc[unix.VSTOP] = uint8(value)
	case 10:
		termios.Cc[unix.VSUSP] = uint8(value)
	case 12:
		termios.Cc[unix.VREPRINT] = uint8(value)
	case 13:
		termios.Cc[unix.VWERASE] = uint8(value)
	case 14:
		termios.Cc[unix.VLNEXT] = uint8(value)
	case 16:
		termios.Cc[unix.VSWTC] = uint8(value)
	case 18:
		termios.Cc[unix.VDISCARD] = uint8(value)
	case 30:
		setFlag(&termios.Iflag, unix.IGNBRK)
	case 31:
		setFlag(&termios.Iflag, unix.BRKINT)
	case 32:
		setFlag(&termios.Iflag, unix.IGNPAR)
	case 33:
		setFlag(&termios.Iflag, unix.PARMRK)
	case 34:
		setFlag(&termios.Iflag, unix.INPCK)
	case 35:
		setFlag(&termios.Iflag, unix.ISTRIP)
	case 36:
		setFlag(&termios.Iflag, unix.INLCR)
	case 37:
		setFlag(&termios.Iflag, unix.IGNCR)
	case 38:
		setFlag(&termios.Iflag, unix.ICRNL)
	case 39:
		setFlag(&termios.Iflag, unix.IUCLC)
	case 40:
		setFlag(&termios.Iflag, unix.IXON)
	case 41:
		setFlag(&termios.Iflag, unix.IXANY)
	case 42:
		setFlag(&termios.Iflag, unix.IXOFF)
	case 43:
		setFlag(&termios.Iflag, unix.IMAXBEL)
	case 44:
		setFlag(&termios.Iflag, unix.IUTF8)
	case 50:
		setFlag(&termios.Lflag, unix.ISIG)
	case 51:
		setFlag(&termios.Lflag, unix.ICANON)
	case 52:
		setFlag(&termios.Lflag, unix.XCASE)
	case 53:
		setFlag(&termios.Lflag, unix.ECHO)
	case 54:
		setFlag(&termios.Lflag, unix.ECHOE)
	case 55:
		setFlag(&termios.Lflag, unix.ECHOK)
	case 56:
		setFlag(&termios.Lflag, unix.ECHONL)
	case 57:
		setFlag(&termios.Lflag, unix.NOFLSH)
	case 58:
		setFlag(&termios.Lflag, unix.TOSTOP)
	case 59:
		setFlag(&termios.Lflag, unix.IEXTEN)
	case 60:
		setFlag(&termios.Lflag, unix.ECHOCTL)
	case 61:
		setFlag(&termios.Lflag, unix.ECHOKE)
	case 62:
		setFlag(&termios.Lflag, unix.PENDIN)
	case 70:
		setFlag(&termios.Oflag, unix.OPOST)
	case 71:
		setFlag(&termios.Oflag, unix.OLCUC)
	case 72:
		setFlag(&termios.Oflag, unix.ONLCR)
	case 73:
		setFlag(&termios.Oflag, unix.OCRNL)
	case 74:
		setFlag(&termios.Oflag, unix.ONOCR)
	case 75:
		setFlag(&termios.Oflag, unix.ONLRET)
	case 90:
		termios.Cflag &^= unix.CSIZE
		termios.Cflag |= unix.CS7
	case 91:
		termios.Cflag &^= unix.CSIZE
		termios.Cflag |= unix.CS8
	case 92:
		setFlag(&termios.Cflag, unix.PARENB)
	case 93:
		setFlag(&termios.Cflag, unix.PARODD)
	case 128:
		termios.Ispeed = value
	case 129:
		termios.Ospeed = value
	}
}
