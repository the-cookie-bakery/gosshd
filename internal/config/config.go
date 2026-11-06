package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type ListenAddress struct {
	Host string
	Port int
}

type Config struct {
	Path string

	Port             int
	ListenAddresses  []ListenAddress
	AddressFamily    string
	HostKeys         []string
	HostCertificates []string
	PidFile          string
	LogLevel         string
	SyslogFacility   string
	MaxStartups      int

	MaxAuthTries                 int
	MaxSessions                  int
	LoginGraceTime               time.Duration
	PasswordAuthentication       bool
	PubkeyAuthentication         bool
	KbdInteractiveAuthentication bool
	PermitEmptyPasswords         bool
	PermitRootLogin              string
	PermitTTY                    bool
	StrictModes                  bool
	PermitUserEnvironment        string
	PermitUserRC                 bool
	PrintMotd                    bool
	PrintLastLog                 bool
	Banner                       string

	AuthorizedKeysFile              []string
	AuthorizedKeysCommand           []string
	AuthorizedKeysCommandUser       string
	AuthorizedPrincipalsCommand     []string
	AuthorizedPrincipalsCommandUser string
	TrustedUserCAKeys               []string
	AuthorizedPrincipalsFile        string
	RevokedKeys                     string

	AcceptEnv  []string
	SetEnv     map[string]string
	Subsystems map[string]string

	ForceCommand    string
	ChrootDirectory string

	ClientAliveInterval time.Duration
	ClientAliveCountMax int
	TCPKeepAlive        bool

	KexAlgorithms            []string
	Ciphers                  []string
	MACs                     []string
	HostKeyAlgorithms        []string
	PubkeyAcceptedAlgorithms []string
	RequiredRSASize          int
	RekeyLimit               int64

	AuthenticationMethods [][]string
	AllowUsers            []string
	DenyUsers             []string
	AllowGroups           []string
	DenyGroups            []string

	UsePAM bool
}

func Default() *Config {
	return &Config{
		Port:                         22,
		AddressFamily:                "any",
		LogLevel:                     "INFO",
		SyslogFacility:               "AUTH",
		MaxStartups:                  10,
		MaxAuthTries:                 6,
		MaxSessions:                  10,
		LoginGraceTime:               120 * time.Second,
		PasswordAuthentication:       true,
		PubkeyAuthentication:         true,
		KbdInteractiveAuthentication: true,
		PermitRootLogin:              "prohibit-password",
		PermitTTY:                    true,
		StrictModes:                  true,
		PermitUserEnvironment:        "no",
		PermitUserRC:                 true,
		PrintMotd:                    true,
		PrintLastLog:                 true,
		AuthorizedKeysFile:           []string{".ssh/authorized_keys", ".ssh/authorized_keys2"},
		SetEnv:                       map[string]string{},
		Subsystems:                   map[string]string{},
		RequiredRSASize:              2048,
		ClientAliveCountMax:          3,
		TCPKeepAlive:                 true,
	}
}

func (c *Config) Clone() *Config {
	d := *c
	d.ListenAddresses = append([]ListenAddress(nil), c.ListenAddresses...)
	d.HostKeys = append([]string(nil), c.HostKeys...)
	d.HostCertificates = append([]string(nil), c.HostCertificates...)
	d.AuthorizedKeysFile = append([]string(nil), c.AuthorizedKeysFile...)
	d.AuthorizedKeysCommand = append([]string(nil), c.AuthorizedKeysCommand...)
	d.AuthorizedPrincipalsCommand = append([]string(nil), c.AuthorizedPrincipalsCommand...)
	d.TrustedUserCAKeys = append([]string(nil), c.TrustedUserCAKeys...)
	d.AcceptEnv = append([]string(nil), c.AcceptEnv...)
	d.KexAlgorithms = append([]string(nil), c.KexAlgorithms...)
	d.Ciphers = append([]string(nil), c.Ciphers...)
	d.MACs = append([]string(nil), c.MACs...)
	d.HostKeyAlgorithms = append([]string(nil), c.HostKeyAlgorithms...)
	d.PubkeyAcceptedAlgorithms = append([]string(nil), c.PubkeyAcceptedAlgorithms...)
	d.AuthenticationMethods = make([][]string, len(c.AuthenticationMethods))
	for i := range c.AuthenticationMethods {
		d.AuthenticationMethods[i] = append([]string(nil), c.AuthenticationMethods[i]...)
	}
	d.AllowUsers = append([]string(nil), c.AllowUsers...)
	d.DenyUsers = append([]string(nil), c.DenyUsers...)
	d.AllowGroups = append([]string(nil), c.AllowGroups...)
	d.DenyGroups = append([]string(nil), c.DenyGroups...)
	d.SetEnv = make(map[string]string, len(c.SetEnv))
	for k, v := range c.SetEnv {
		d.SetEnv[k] = v
	}
	d.Subsystems = make(map[string]string, len(c.Subsystems))
	for k, v := range c.Subsystems {
		d.Subsystems[k] = v
	}
	return &d
}

func (c *Config) Validate() error {
	if len(c.AuthorizedKeysCommand) > 0 && c.AuthorizedKeysCommandUser == "" {
		return fmt.Errorf("AuthorizedKeysCommand requires AuthorizedKeysCommandUser")
	}
	if len(c.AuthorizedPrincipalsCommand) > 0 && c.AuthorizedPrincipalsCommandUser == "" {
		return fmt.Errorf("AuthorizedPrincipalsCommand requires AuthorizedPrincipalsCommandUser")
	}
	for _, alternative := range c.AuthenticationMethods {
		for _, method := range alternative {
			switch method {
			case "publickey":
				if !c.PubkeyAuthentication {
					return fmt.Errorf("AuthenticationMethods uses publickey but PubkeyAuthentication is disabled")
				}
			case "password":
				if !c.PasswordAuthentication {
					return fmt.Errorf("AuthenticationMethods uses password but PasswordAuthentication is disabled")
				}
			case "keyboard-interactive":
				if !c.KbdInteractiveAuthentication {
					return fmt.Errorf("AuthenticationMethods uses keyboard-interactive but KbdInteractiveAuthentication is disabled")
				}
			default:
				return fmt.Errorf("unsupported AuthenticationMethods method %q", method)
			}
		}
	}
	return nil
}

func (c *Config) Listeners() ([]string, error) {
	var out []string
	if len(c.ListenAddresses) == 0 {
		switch c.AddressFamily {
		case "", "any":
			out = append(out, net.JoinHostPort("", strconv.Itoa(c.Port)))
		case "inet":
			out = append(out, net.JoinHostPort("0.0.0.0", strconv.Itoa(c.Port)))
		case "inet6":
			out = append(out, net.JoinHostPort("::", strconv.Itoa(c.Port)))
		default:
			return nil, &ParseError{Message: "invalid AddressFamily " + c.AddressFamily}
		}
		return out, nil
	}
	for _, la := range c.ListenAddresses {
		port := la.Port
		if port == 0 {
			port = c.Port
		}
		out = append(out, net.JoinHostPort(la.Host, strconv.Itoa(port)))
	}
	return out, nil
}

func parseDuration(v string) (time.Duration, error) {
	if v == "" {
		return 0, &ParseError{Message: "empty time value"}
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}

func parseSize(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, &ParseError{Message: "empty size value"}
	}
	mult := int64(1)
	last := v[len(v)-1]
	switch last {
	case 'K', 'k':
		mult = 1024
		v = v[:len(v)-1]
	case 'M', 'm':
		mult = 1024 * 1024
		v = v[:len(v)-1]
	case 'G', 'g':
		mult = 1024 * 1024 * 1024
		v = v[:len(v)-1]
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, &ParseError{Message: "negative size"}
	}
	return n * mult, nil
}
