package auth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/config"
	"github.com/cookiengineer/gosshd/internal/nss"
)

func (a *Authenticator) lookupAuthorizedKey(cfg *config.Config, u *nss.User, key ssh.PublicKey, remote, local net.Addr) (*Permissions, error) {
	if cert, ok := key.(*ssh.Certificate); ok {
		perms, found, err := a.lookupAuthorizedCertAuthorities(cfg, u, cert, remote, local)
		if err != nil {
			return nil, err
		}
		if found {
			return perms, nil
		}
		return a.lookupCertificate(cfg, u, cert, remote, local)
	}
	for _, spec := range cfg.AuthorizedKeysFile {
		if spec == "none" {
			continue
		}
		expanded, err := expandTokens(spec, u)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(expanded) {
			expanded = filepath.Join(u.Home, expanded)
		}
		if err := secureAuthorizedKeysFile(u, expanded, cfg.StrictModes); err != nil {
			continue
		}
		f, err := os.Open(expanded)
		if err != nil {
			continue
		}
		p, found, err := scanAuthorizedKeys(f, key, u, remote)
		f.Close()
		if err != nil {
			continue
		}
		if found {
			return p, nil
		}
	}
	if a.keysCommand != nil {
		ctx := keyTokenContext(u, key, remote, local)
		if data, err := a.keysCommand.run(ctx, false); err == nil {
			if p, found, err := scanAuthorizedKeys(bytes.NewReader(data), key, u, remote); err == nil && found {
				return p, nil
			}
		}
	}
	return nil, ErrAccessDenied
}

func scanAuthorizedKeys(r io.Reader, key ssh.PublicKey, u *nss.User, remote net.Addr) (*Permissions, bool, error) {
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 512*1024)
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, _, options, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		if !bytes.Equal(pub.Marshal(), key.Marshal()) {
			continue
		}
		p, err := parseKeyOptions(options, u, remote)
		if err != nil {
			return nil, false, err
		}
		return p, true, nil
	}
	if err := scan.Err(); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

func parseKeyOptions(options []string, u *nss.User, remote net.Addr) (*Permissions, error) {
	p := &Permissions{KeyOptions: map[string]string{}}
	for _, raw := range options {
		name, value, hasValue := strings.Cut(raw, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if hasValue {
			value = strings.TrimSpace(value)
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
		}
		switch name {
		case "from":
			if !sourceAllowed(value, remote) {
				return nil, ErrAccessDenied
			}
			p.SourceAddress = value
		case "command":
			p.ForceCommand = value
		case "environment":
			p.Environment = append(p.Environment, value)
		case "no-pty":
			p.NoPTY = true
		case "no-user-rc":
			p.NoUserRC = true
		case "restrict":
			p.NoPTY = true
			p.NoUserRC = true
		case "no-port-forwarding", "no-agent-forwarding", "no-x11-forwarding":
		case "cert-authority":
			p.CertAuthority = true
		case "principals":
			p.Principals = splitList(value)
		case "expiry-time":
			t, err := parseExpiry(value)
			if err != nil || time.Now().After(t) {
				return nil, ErrAccessDenied
			}
		case "no-touch-required", "verify-required":
		case "permitopen", "permitlisten":
		case "tunnel":
			return nil, ErrAccessDenied
		default:
			return nil, ErrAccessDenied
		}
		p.KeyOptions[name] = value
	}
	_ = u
	return p, nil
}

func sourceAllowed(patterns string, remote net.Addr) bool {
	if patterns == "" {
		return false
	}
	host := ""
	if remote != nil {
		host = remote.String()
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	ip := net.ParseIP(host)
	for _, pat := range strings.Split(patterns, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if strings.Contains(pat, "/") {
			_, cidr, err := net.ParseCIDR(pat)
			if err == nil && ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if pat == host {
			return true
		}
		if ok, _ := filepath.Match(pat, host); ok {
			return true
		}
		if ip != nil && net.ParseIP(pat) != nil && net.ParseIP(pat).Equal(ip) {
			return true
		}
	}
	return false
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseExpiry(v string) (time.Time, error) {
	for _, layout := range []string{"20060102150405", "200601021504", "20060102"} {
		if t, err := time.ParseInLocation(layout, v, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid expiry-time %q", v)
}

func expandTokens(spec string, u *nss.User) (string, error) {
	var b strings.Builder
	for i := 0; i < len(spec); i++ {
		if spec[i] != '%' {
			b.WriteByte(spec[i])
			continue
		}
		i++
		if i >= len(spec) {
			return "", errors.New("trailing % in token")
		}
		switch spec[i] {
		case '%':
			b.WriteByte('%')
		case 'h':
			b.WriteString(u.Home)
		case 'u':
			b.WriteString(u.Name)
		case 'U':
			b.WriteString(strconv.FormatUint(uint64(u.UID), 10))
		case 'g':
			if len(u.Groups) > 0 {
				b.WriteString(u.Groups[0])
			}
		default:
			return "", fmt.Errorf("unsupported token %%%c", spec[i])
		}
	}
	return b.String(), nil
}

func secureAuthorizedKeysFile(u *nss.User, path string, strict bool) error {
	if !strict {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("authorized_keys is a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("authorized_keys is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("authorized_keys is group or world writable")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if ok && st.Uid != 0 && st.Uid != u.UID {
		return errors.New("authorized_keys has invalid owner")
	}
	if err := secureDir(filepath.Dir(path), u, strict); err != nil {
		return err
	}
	return nil
}

func secureDir(dir string, u *nss.User, strict bool) error {
	if !strict {
		return nil
	}
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("directory is a symlink")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return errors.New("directory is group or world writable")
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && st.Uid != u.UID {
			return errors.New("directory has invalid owner")
		}
		if dir == u.Home || dir == "/" || dir == filepath.Dir(dir) {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil
}
