package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-crypt/crypt"
	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/config"
	"github.com/cookiengineer/gosshd/internal/nss"
)

const (
	maxPasswordLength = 1024
	dummyPasswordHash = "$y$j75$z7ztFz2FayrKI79/jEwlL.$u5x/j193MQ09wbFaRGYr0AH/A/jh3kunjuhYRVRNkmC"
)

var (
	ErrAccountLocked  = errors.New("account is locked")
	ErrAccountExpired = errors.New("account is expired")
	ErrAccessDenied   = errors.New("access denied")
	ErrInvalidLogin   = errors.New("invalid user or password")
)

type Permissions struct {
	Username      string
	UID           uint32
	GID           uint32
	Groups        []string
	Home          string
	Shell         string
	ForceCommand  string
	SourceAddress string
	Environment   []string
	NoPTY         bool
	NoUserRC      bool
	CertAuthority bool
	Principals    []string
	KeyOptions    map[string]string
}

type Authenticator struct {
	cfg     *config.Config
	decoder *crypt.Decoder
}

func New(cfg *config.Config) (*Authenticator, error) {
	d, err := crypt.NewDefaultDecoder()
	if err != nil {
		return nil, err
	}
	return &Authenticator{cfg: cfg, decoder: d}, nil
}

func (a *Authenticator) Config() *config.Config {
	return a.cfg
}

func (a *Authenticator) Lookup(username string, remote net.Addr) (*nss.User, error) {
	u, err := nss.LookupUser(username)
	if err != nil {
		return nil, ErrInvalidLogin
	}
	if u.Shell == "" {
		u.Shell = "/bin/sh"
	}
	if err := a.checkAccess(u, remote); err != nil {
		return nil, err
	}
	return u, nil
}

func (a *Authenticator) Password(username string, password []byte, remote net.Addr) (*Permissions, error) {
	if len(password) > maxPasswordLength {
		return nil, ErrInvalidLogin
	}
	u, err := a.Lookup(username, remote)
	if err != nil {
		a.dummyVerify(password)
		return nil, err
	}
	if err := a.checkRootLogin(u, "password", false); err != nil {
		return nil, err
	}
	if err := a.checkNologin(u); err != nil {
		return nil, err
	}
	sh, err := nss.LookupShadow(username)
	if err != nil {
		return nil, ErrInvalidLogin
	}
	now := time.Now()
	days := now.Unix() / 86400
	if sh.Expire >= 0 && days >= sh.Expire {
		return nil, ErrAccountExpired
	}
	if sh.LastChange >= 0 && sh.Max >= 0 && sh.Max > 0 && days > sh.LastChange+sh.Max+max64(sh.Inact, 0) {
		return nil, ErrAccountExpired
	}
	if sh.LastChange == 0 && sh.Max > 0 {
		return nil, ErrAccountExpired
	}
	hash := sh.Hash
	if strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*") {
		return nil, ErrAccountLocked
	}
	if hash == "" {
		if !a.cfg.PermitEmptyPasswords || len(password) != 0 {
			return nil, ErrInvalidLogin
		}
	} else {
		digest, err := a.decoder.Decode(hash)
		if err != nil {
			return nil, ErrInvalidLogin
		}
		ok, err := digest.MatchAdvanced(string(password))
		if err != nil || !ok {
			return nil, ErrInvalidLogin
		}
	}
	return &Permissions{
		Username: u.Name,
		UID:      u.UID,
		GID:      u.GID,
		Groups:   u.Groups,
		Home:     u.Home,
		Shell:    u.Shell,
	}, nil
}

func (a *Authenticator) PublicKey(username string, key ssh.PublicKey, remote net.Addr) (*Permissions, error) {
	u, err := a.Lookup(username, remote)
	if err != nil {
		return nil, err
	}
	if !a.cfg.PubkeyAuthentication {
		return nil, ErrAccessDenied
	}
	if err := checkRSASize(key, a.cfg.RequiredRSASize); err != nil {
		return nil, err
	}
	p, err := a.lookupAuthorizedKey(u, key, remote)
	if err != nil {
		return nil, err
	}
	if err := a.checkRootLogin(u, "publickey", p.ForceCommand != ""); err != nil {
		return nil, err
	}
	if err := a.checkNologin(u); err != nil {
		return nil, err
	}
	p.Username = u.Name
	p.UID = u.UID
	p.GID = u.GID
	p.Groups = u.Groups
	p.Home = u.Home
	p.Shell = u.Shell
	return p, nil
}

func (a *Authenticator) dummyVerify(password []byte) {
	digest, err := a.decoder.Decode(dummyPasswordHash)
	if err != nil {
		return
	}
	_, _ = digest.MatchAdvanced(string(password))
}

func checkRSASize(key ssh.PublicKey, minimum int) error {
	if minimum <= 0 {
		return nil
	}
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}
	cpk, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return nil
	}
	pub, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return nil
	}
	if pub.N.BitLen() < minimum {
		return ErrAccessDenied
	}
	return nil
}

func (a *Authenticator) checkRootLogin(u *nss.User, method string, forced bool) error {
	if u.UID != 0 {
		return nil
	}
	switch strings.ToLower(a.cfg.PermitRootLogin) {
	case "no":
		return ErrAccessDenied
	case "yes":
		return nil
	case "forced-commands-only":
		if !forced {
			return ErrAccessDenied
		}
		return nil
	case "prohibit-password", "without-password":
		if method != "publickey" {
			return ErrAccessDenied
		}
		return nil
	}
	return ErrAccessDenied
}

func (a *Authenticator) checkNologin(u *nss.User) error {
	if u.UID == 0 {
		return nil
	}
	if _, err := os.Stat("/etc/nologin"); err == nil {
		return ErrAccessDenied
	}
	return nil
}

func (a *Authenticator) checkAccess(u *nss.User, remote net.Addr) error {
	for _, pat := range a.cfg.DenyUsers {
		if matchUserHost(pat, u.Name, remote) {
			return ErrAccessDenied
		}
	}
	for _, pat := range a.cfg.AllowUsers {
		if matchUserHost(pat, u.Name, remote) {
			goto groups
		}
	}
	if len(a.cfg.AllowUsers) > 0 {
		return ErrAccessDenied
	}
groups:
	for _, pat := range a.cfg.DenyGroups {
		for _, g := range u.Groups {
			if matchGlob(pat, g) {
				return ErrAccessDenied
			}
		}
	}
	if len(a.cfg.AllowGroups) > 0 {
		for _, pat := range a.cfg.AllowGroups {
			for _, g := range u.Groups {
				if matchGlob(pat, g) {
					return nil
				}
			}
		}
		return ErrAccessDenied
	}
	return nil
}

func matchUserHost(pat, username string, remote net.Addr) bool {
	if i := strings.LastIndex(pat, "@"); i >= 0 {
		up, hp := pat[:i], pat[i+1:]
		if !matchGlob(up, username) {
			return false
		}
		host := ""
		if remote != nil {
			host = remote.String()
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		if strings.Contains(hp, "/") {
			ip := net.ParseIP(host)
			_, cidr, err := net.ParseCIDR(hp)
			return err == nil && ip != nil && cidr.Contains(ip)
		}
		return matchGlob(hp, host)
	}
	return matchGlob(pat, username)
}

func matchGlob(pat, s string) bool {
	ok, err := path.Match(pat, s)
	return err == nil && ok
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (a *Authenticator) SSHPermissions(p *Permissions) interface{} {
	return p
}

func (a *Authenticator) UnknownUserPassword(username string) error {
	return fmt.Errorf("%w", ErrInvalidLogin)
}
