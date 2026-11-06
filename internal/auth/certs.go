package auth

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/nss"
)

func (a *Authenticator) lookupAuthorizedCertAuthorities(u *nss.User, cert *ssh.Certificate, remote net.Addr) (*Permissions, bool, error) {
	if cert.CertType != ssh.UserCert {
		return nil, false, nil
	}
	for _, spec := range a.cfg.AuthorizedKeysFile {
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
		if err := secureAuthorizedKeysFile(u, expanded, a.cfg.StrictModes); err != nil {
			continue
		}
		perms, found, err := scanCertAuthorityFile(expanded, cert, u, remote)
		if err != nil {
			continue
		}
		if found {
			return perms, true, nil
		}
	}
	return nil, false, nil
}

func scanCertAuthorityFile(path string, cert *ssh.Certificate, u *nss.User, remote net.Addr) (*Permissions, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 64*1024), 512*1024)
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		ca, _, options, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		p, err := parseKeyOptions(options, u, remote)
		if err != nil || !p.CertAuthority {
			continue
		}
		if cert.SignatureKey == nil || !bytes.Equal(ca.Marshal(), cert.SignatureKey.Marshal()) {
			continue
		}
		principals := p.Principals
		if len(principals) == 0 {
			principals = []string{u.Name}
		}
		checker := &ssh.CertChecker{
			SupportedCriticalOptions: []string{"force-command", "source-address"},
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				return bytes.Equal(ca.Marshal(), auth.Marshal())
			},
		}
		valid := false
		for _, principal := range principals {
			if checker.CheckCert(principal, cert) == nil {
				valid = true
				break
			}
		}
		if !valid {
			continue
		}
		perms, err := certificatePermissions(cert, remote)
		if err != nil {
			continue
		}
		if p.ForceCommand != "" {
			perms.ForceCommand = p.ForceCommand
		}
		if p.NoPTY {
			perms.NoPTY = true
		}
		if p.NoUserRC {
			perms.NoUserRC = true
		}
		perms.Environment = append(perms.Environment, p.Environment...)
		return perms, true, nil
	}
	if err := scan.Err(); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

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
	return certificatePermissions(cert, remote)
}

func certificatePermissions(cert *ssh.Certificate, remote net.Addr) (*Permissions, error) {
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
