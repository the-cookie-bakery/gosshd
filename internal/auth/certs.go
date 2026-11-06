package auth

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/config"
	"github.com/cookiengineer/gosshd/internal/nss"
)

func (a *Authenticator) lookupAuthorizedCertAuthorities(cfg *config.Config, u *nss.User, cert *ssh.Certificate, remote, local net.Addr) (*Permissions, bool, error) {
	if cert.CertType != ssh.UserCert {
		return nil, false, nil
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
		perms, found, err := scanCertAuthority(f, cert, u, remote)
		f.Close()
		if err != nil {
			continue
		}
		if found {
			return perms, true, nil
		}
	}
	if a.keysCommand != nil {
		ctx := certTokenContext(u, cert, remote, local)
		if data, err := a.keysCommand.run(ctx, true); err == nil {
			if perms, found, err := scanCertAuthority(bytes.NewReader(data), cert, u, remote); err == nil && found {
				return perms, true, nil
			}
		}
	}
	return nil, false, nil
}

func scanCertAuthority(r io.Reader, cert *ssh.Certificate, u *nss.User, remote net.Addr) (*Permissions, bool, error) {
	scan := bufio.NewScanner(r)
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

func (a *Authenticator) lookupCertificate(cfg *config.Config, u *nss.User, cert *ssh.Certificate, remote, local net.Addr) (*Permissions, error) {
	if cert.CertType != ssh.UserCert {
		return nil, ErrAccessDenied
	}
	authorities, err := loadAuthorities(cfg.TrustedUserCAKeys)
	if err != nil || len(authorities) == 0 {
		return nil, ErrAccessDenied
	}
	revoked, _ := loadRevoked(cfg.RevokedKeys)
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
	if cfg.AuthorizedPrincipalsFile != "" {
		allowed, err := readPrincipalsFile(cfg.AuthorizedPrincipalsFile)
		if err != nil {
			return nil, ErrAccessDenied
		}
		principal = matchPrincipal(cert, allowed)
		if principal == "" {
			return nil, ErrAccessDenied
		}
	} else if a.principalsCommand != nil {
		ctx := certTokenContext(u, cert, remote, local)
		data, err := a.principalsCommand.run(ctx, true)
		if err != nil {
			return nil, ErrAccessDenied
		}
		allowed, err := readPrincipals(bytes.NewReader(data))
		if err != nil {
			return nil, ErrAccessDenied
		}
		principal = matchPrincipal(cert, allowed)
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

func readPrincipalsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readPrincipals(f)
}

func readPrincipals(r io.Reader) ([]string, error) {
	var out []string
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no principals")
	}
	return out, nil
}

func matchPrincipal(cert *ssh.Certificate, allowed []string) string {
	for _, principal := range cert.ValidPrincipals {
		for _, candidate := range allowed {
			if principal == candidate {
				return principal
			}
		}
	}
	return ""
}
