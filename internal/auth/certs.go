package auth

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/nss"
)

func (a *Authenticator) lookupCertificate(u *nss.User, cert *ssh.Certificate, remote net.Addr) (*Permissions, error) {
	if cert.CertType != ssh.UserCert {
		return nil, ErrAccessDenied
	}
	authorities, err := loadAuthorities(a.cfg.TrustedUserCAKeys)
	if err != nil || len(authorities) == 0 {
		return nil, ErrAccessDenied
	}
	revoked, _ := loadRevoked(a.cfg.RevokedKeys)
	checker := &ssh.CertChecker{
		SupportedCriticalOptions: []string{"force-command", "source-address"},
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			for _, ca := range authorities {
				if bytes.Equal(ca.Marshal(), auth.Marshal()) {
					return true
				}
			}
			return false
		},
		IsRevoked: func(c *ssh.Certificate) bool {
			for _, r := range revoked {
				if bytes.Equal(r.Marshal(), c.Marshal()) || bytes.Equal(r.Marshal(), c.Key.Marshal()) {
					return true
				}
			}
			return false
		},
	}
	principal := u.Name
	if a.cfg.AuthorizedPrincipalsFile != "" {
		allowed, err := readPrincipals(a.cfg.AuthorizedPrincipalsFile)
		if err != nil {
			return nil, ErrAccessDenied
		}
		principal = ""
		for _, p := range cert.ValidPrincipals {
			for _, candidate := range allowed {
				if p == candidate {
					principal = p
					break
				}
			}
			if principal != "" {
				break
			}
		}
		if principal == "" {
			return nil, ErrAccessDenied
		}
	}
	if err := checker.CheckCert(principal, cert); err != nil {
		return nil, ErrAccessDenied
	}
	p := &Permissions{KeyOptions: map[string]string{}}
	if v := cert.CriticalOptions["force-command"]; v != "" {
		p.ForceCommand = v
	}
	if v := cert.CriticalOptions["source-address"]; v != "" {
		if !sourceAllowed(v, remote) {
			return nil, ErrAccessDenied
		}
		p.SourceAddress = v
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		p.NoPTY = true
	}
	if _, ok := cert.Extensions["permit-user-rc"]; !ok {
		p.NoUserRC = true
	}
	if v := cert.Extensions["permit-X11-forwarding"]; v != "" {
		_ = v
	}
	return p, nil
}

func loadAuthorities(paths []string) ([]ssh.PublicKey, error) {
	var out []ssh.PublicKey
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		scan := bufio.NewScanner(f)
		for scan.Scan() {
			line := bytes.TrimSpace(scan.Bytes())
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			key, _, _, _, err := ssh.ParseAuthorizedKey(line)
			if err == nil {
				out = append(out, key)
			}
		}
		err = scan.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func loadRevoked(path string) ([]ssh.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ssh.PublicKey
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
			out = append(out, key)
			continue
		}
		if key, err := ssh.ParsePublicKey([]byte(line)); err == nil {
			out = append(out, key)
		}
	}
	return out, scan.Err()
}

func readPrincipals(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, errors.New("no principals")
	}
	return out, nil
}
