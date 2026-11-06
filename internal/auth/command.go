package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/nss"
)

const (
	commandTimeout     = 5 * time.Second
	commandOutputLimit = 512 * 1024
)

type commandSpec struct {
	argv   []string
	user   string
	uid    uint32
	gid    uint32
	groups []uint32
	home   string
}

func newCommandSpec(argv []string, username string) (*commandSpec, error) {
	if len(argv) == 0 {
		return nil, nil
	}
	if username == "" {
		return nil, errors.New("authorized command requires a command user")
	}
	if !filepath.IsAbs(argv[0]) {
		return nil, fmt.Errorf("authorized command %q must be an absolute path", argv[0])
	}
	info, err := os.Stat(argv[0])
	if err != nil {
		return nil, fmt.Errorf("authorized command %s: %w", argv[0], err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("authorized command %s is not a regular file", argv[0])
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return nil, fmt.Errorf("authorized command %s is not owned by root", argv[0])
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("authorized command %s is group or world writable", argv[0])
	}
	u, err := nss.LookupUser(username)
	if err != nil {
		return nil, fmt.Errorf("authorized command user %q: %w", username, err)
	}
	var groups []uint32
	for _, name := range u.Groups {
		if g, err := nss.LookupGroup(name); err == nil {
			groups = append(groups, g.GID)
		}
	}
	return &commandSpec{
		argv:   append([]string(nil), argv...),
		user:   u.Name,
		uid:    u.UID,
		gid:    u.GID,
		groups: groups,
		home:   u.Home,
	}, nil
}

type tokenContext struct {
	username      string
	uid           string
	home          string
	keyType       string
	keyBlob       string
	fingerprint   string
	connection    string
	keyID         string
	serial        string
	caType        string
	caBlob        string
	caFingerprint string
}

func keyTokenContext(u *nss.User, key ssh.PublicKey, remote, local net.Addr) tokenContext {
	return tokenContext{
		username:    u.Name,
		uid:         strconv.FormatUint(uint64(u.UID), 10),
		home:        u.Home,
		keyType:     key.Type(),
		keyBlob:     base64.StdEncoding.EncodeToString(key.Marshal()),
		fingerprint: ssh.FingerprintSHA256(key),
		connection:  connectionEndpoints(remote, local),
	}
}

func certTokenContext(u *nss.User, cert *ssh.Certificate, remote, local net.Addr) tokenContext {
	ctx := tokenContext{
		username:    u.Name,
		uid:         strconv.FormatUint(uint64(u.UID), 10),
		home:        u.Home,
		keyType:     cert.Type(),
		keyBlob:     base64.StdEncoding.EncodeToString(cert.Marshal()),
		fingerprint: ssh.FingerprintSHA256(cert),
		connection:  connectionEndpoints(remote, local),
		keyID:       cert.KeyId,
		serial:      strconv.FormatUint(cert.Serial, 10),
	}
	if cert.SignatureKey != nil {
		ctx.caType = cert.SignatureKey.Type()
		ctx.caBlob = base64.StdEncoding.EncodeToString(cert.SignatureKey.Marshal())
		ctx.caFingerprint = ssh.FingerprintSHA256(cert.SignatureKey)
	}
	return ctx
}

func connectionEndpoints(remote, local net.Addr) string {
	parts := []string{"", "", "", ""}
	if remote != nil {
		if host, port, err := net.SplitHostPort(remote.String()); err == nil {
			parts[0], parts[1] = host, port
		} else {
			parts[0] = remote.String()
		}
	}
	if local != nil {
		if host, port, err := net.SplitHostPort(local.String()); err == nil {
			parts[2], parts[3] = host, port
		} else {
			parts[2] = local.String()
		}
	}
	return strings.Join(parts, " ")
}

func expandCommandArg(arg string, ctx tokenContext, allowCert bool) (string, error) {
	var b strings.Builder
	for i := 0; i < len(arg); i++ {
		if arg[i] != '%' {
			b.WriteByte(arg[i])
			continue
		}
		i++
		if i >= len(arg) {
			return "", errors.New("trailing % in authorized command")
		}
		switch arg[i] {
		case '%':
			b.WriteByte('%')
		case 'C':
			b.WriteString(ctx.connection)
		case 'D':
			// Routing domains are not supported; expand to an empty value.
		case 'f':
			b.WriteString(ctx.fingerprint)
		case 'h':
			b.WriteString(ctx.home)
		case 'k':
			b.WriteString(ctx.keyBlob)
		case 't':
			b.WriteString(ctx.keyType)
		case 'U':
			b.WriteString(ctx.uid)
		case 'u':
			b.WriteString(ctx.username)
		case 'F', 'i', 'K', 's', 'T':
			if !allowCert {
				return "", fmt.Errorf("token %%%c is not allowed for this command", arg[i])
			}
			switch arg[i] {
			case 'F':
				b.WriteString(ctx.caFingerprint)
			case 'i':
				b.WriteString(ctx.keyID)
			case 'K':
				b.WriteString(ctx.caBlob)
			case 's':
				b.WriteString(ctx.serial)
			case 'T':
				b.WriteString(ctx.caType)
			}
		default:
			return "", fmt.Errorf("unsupported token %%%c", arg[i])
		}
	}
	return b.String(), nil
}

func (c *commandSpec) run(ctx tokenContext, allowCert bool) ([]byte, error) {
	args := make([]string, len(c.argv))
	args[0] = c.argv[0]
	for i := 1; i < len(c.argv); i++ {
		expanded, err := expandCommandArg(c.argv[i], ctx, allowCert)
		if err != nil {
			return nil, err
		}
		args[i] = expanded
	}
	if len(c.argv) == 1 {
		args = append(args, ctx.username)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, args[0], args[1:]...)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + c.home,
		"USER=" + c.user,
		"LOGNAME=" + c.user,
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid:    c.uid,
		Gid:    c.gid,
		Groups: c.groups,
	}}
	out := &limitedBuffer{max: commandOutputLimit}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.buf.Bytes(), nil
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		return 0, errors.New("authorized command output too large")
	}
	return w.buf.Write(p)
}
