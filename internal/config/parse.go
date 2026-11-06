package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ParseError struct {
	Path    string
	Line    int
	Message string
}

func (e *ParseError) Error() string {
	if e.Path == "" {
		return e.Message
	}
	if e.Line == 0 {
		return e.Path + ": " + e.Message
	}
	return fmt.Sprintf("%s:%d: %s", e.Path, e.Line, e.Message)
}

type parser struct {
	cfg       *Config
	seen      map[string]bool
	match     *MatchBlock
	matchSeen map[string]bool
	baseDir   string
	depth     int
	included  map[string]bool
}

func ParseFile(path string) (*Config, error) {
	p := &parser{cfg: Default(), seen: map[string]bool{}, included: map[string]bool{}}
	if err := p.parseFile(path); err != nil {
		return nil, err
	}
	p.cfg.Path = path
	return p.cfg, nil
}

func ParseReader(r io.Reader, name string) (*Config, error) {
	p := &parser{cfg: Default(), seen: map[string]bool{}, included: map[string]bool{}, baseDir: filepath.Dir(name)}
	if err := p.parseReader(r, name); err != nil {
		return nil, err
	}
	p.cfg.Path = name
	return p.cfg, nil
}

func ParseOption(cfg *Config, option string) error {
	if cfg.explicit == nil {
		cfg.explicit = map[string]bool{}
	}
	p := &parser{cfg: cfg, seen: map[string]bool{}, included: map[string]bool{}}
	fields, err := splitFields(option)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return &ParseError{Message: "empty option"}
	}
	return p.apply(fields[0], fields[1:], "")
}

func (p *parser) parseFile(path string) error {
	if p.depth > 16 {
		return &ParseError{Path: path, Message: "include depth exceeded"}
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if p.included[clean] {
		return &ParseError{Path: path, Message: "recursive include"}
	}
	p.included[clean] = true
	defer delete(p.included, clean)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	old := p.baseDir
	p.baseDir = filepath.Dir(path)
	p.depth++
	defer func() { p.depth--; p.baseDir = old }()
	return p.parseReader(f, path)
}

func (p *parser) parseReader(r io.Reader, name string) error {
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for scan.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(scan.Text()))
		if line == "" {
			continue
		}
		fields, err := splitFields(line)
		if err != nil {
			return &ParseError{Path: name, Line: lineNo, Message: err.Error()}
		}
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "include" {
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(p.baseDir, pattern)
				}
				matches, err := filepath.Glob(pattern)
				if err != nil {
					return &ParseError{Path: name, Line: lineNo, Message: err.Error()}
				}
				for _, m := range matches {
					if err := p.parseFile(m); err != nil {
						return err
					}
				}
			}
			continue
		}
		if key == "match" {
			block, err := parseMatchCriteria(fields[1:])
			if err != nil {
				return &ParseError{Path: name, Line: lineNo, Message: err.Error()}
			}
			p.cfg.Matches = append(p.cfg.Matches, block)
			p.match = &p.cfg.Matches[len(p.cfg.Matches)-1]
			p.matchSeen = map[string]bool{}
			continue
		}
		if p.match != nil {
			err = setMatchDirective(p.match, p.matchSeen, fields[0], fields[1:])
		} else {
			err = p.apply(fields[0], fields[1:], name)
		}
		if err != nil {
			return &ParseError{Path: name, Line: lineNo, Message: err.Error()}
		}
	}
	if err := scan.Err(); err != nil {
		return &ParseError{Path: name, Message: err.Error()}
	}
	return nil
}

func (p *parser) first(key string) bool {
	k := strings.ToLower(key)
	if p.seen[k] {
		return false
	}
	p.seen[k] = true
	return true
}

func (p *parser) apply(key string, args []string, source string) error {
	k := strings.ToLower(key)
	require := func(n int) error {
		if len(args) < n {
			return fmt.Errorf("%s requires %d argument(s)", key, n)
		}
		return nil
	}
	one := func() (string, error) {
		if err := require(1); err != nil {
			return "", err
		}
		return args[0], nil
	}
	yesNo := func() (bool, error) {
		v, err := one()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(v) {
		case "yes", "true", "on":
			return true, nil
		case "no", "false", "off":
			return false, nil
		default:
			return false, fmt.Errorf("%s must be yes or no", key)
		}
	}

	switch k {
	case "port":
		v, err := one()
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid Port %q", v)
		}
		if p.first(k) {
			p.cfg.Port = n
		}
	case "listenaddress":
		v, err := one()
		if err != nil {
			return err
		}
		host, port := splitListenAddress(v)
		p.cfg.ListenAddresses = append(p.cfg.ListenAddresses, ListenAddress{Host: host, Port: port})
	case "addressfamily":
		v, err := one()
		if err != nil {
			return err
		}
		switch strings.ToLower(v) {
		case "any", "inet", "inet6":
			if p.first(k) {
				p.cfg.AddressFamily = strings.ToLower(v)
			}
		default:
			return fmt.Errorf("invalid AddressFamily %q", v)
		}
	case "hostkey", "hostcertificate":
		v, err := one()
		if err != nil {
			return err
		}
		if k == "hostkey" {
			p.cfg.HostKeys = append(p.cfg.HostKeys, v)
		} else {
			p.cfg.HostCertificates = append(p.cfg.HostCertificates, v)
		}
	case "pidfile":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PidFile = v
		}
	case "loglevel":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.LogLevel = strings.ToUpper(v)
		}
	case "syslogfacility":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.SyslogFacility = strings.ToUpper(v)
		}
	case "maxstartups":
		v, err := one()
		if err != nil {
			return err
		}
		start, rate, full, err := parseMaxStartups(v)
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.MaxStartups = start
			p.cfg.MaxStartupsRate = rate
			p.cfg.MaxStartupsFull = full
		}
	case "maxauthtries":
		v, err := one()
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("invalid MaxAuthTries %q", v)
		}
		if p.first(k) {
			p.cfg.MaxAuthTries = n
		}
	case "maxsessions":
		v, err := one()
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid MaxSessions %q", v)
		}
		if p.first(k) {
			p.cfg.MaxSessions = n
		}
	case "logingracetime":
		v, err := one()
		if err != nil {
			return err
		}
		d, err := parseDuration(v)
		if err != nil || d < 0 {
			return fmt.Errorf("invalid LoginGraceTime %q", v)
		}
		if p.first(k) {
			p.cfg.LoginGraceTime = d
		}
	case "passwordauthentication":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PasswordAuthentication = v
		}
	case "pubkeyauthentication":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PubkeyAuthentication = v
		}
	case "kbdinteractiveauthentication", "challengeresponseauthentication":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first("kbdinteractiveauthentication") {
			p.cfg.KbdInteractiveAuthentication = v
		}
	case "permitemptypasswords":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PermitEmptyPasswords = v
		}
	case "permitrootlogin":
		v, err := one()
		if err != nil {
			return err
		}
		v = strings.ToLower(v)
		if v == "without-password" {
			v = "prohibit-password"
		}
		switch v {
		case "yes", "no", "prohibit-password", "forced-commands-only":
			if p.first(k) {
				p.cfg.PermitRootLogin = v
			}
		default:
			return fmt.Errorf("invalid PermitRootLogin %q", v)
		}
	case "permittty":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PermitTTY = v
		}
	case "strictmodes":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.StrictModes = v
		}
	case "permituserenvironment":
		if len(args) < 1 {
			return errors.New("PermitUserEnvironment requires an argument")
		}
		if p.first(k) {
			p.cfg.PermitUserEnvironment = args[0]
		}
	case "permituserrc":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PermitUserRC = v
		}
	case "printmotd":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PrintMotd = v
		}
	case "printlastlog":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.PrintLastLog = v
		}
	case "banner":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.Banner = v
		}
	case "authorizedkeysfile":
		if p.first(k) {
			p.cfg.AuthorizedKeysFile = nil
		}
		p.cfg.AuthorizedKeysFile = append(p.cfg.AuthorizedKeysFile, args...)
	case "authorizedkeyscommand":
		if err := require(1); err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.AuthorizedKeysCommand = append([]string(nil), args...)
		}
	case "authorizedkeyscommanduser":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.AuthorizedKeysCommandUser = v
		}
	case "authorizedprincipalscommand":
		if err := require(1); err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.AuthorizedPrincipalsCommand = append([]string(nil), args...)
		}
	case "authorizedprincipalscommanduser":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.AuthorizedPrincipalsCommandUser = v
		}
	case "trustedusercakeys":
		v, err := one()
		if err != nil {
			return err
		}
		p.cfg.TrustedUserCAKeys = append(p.cfg.TrustedUserCAKeys, v)
	case "authorizedprincipalsfile":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.AuthorizedPrincipalsFile = v
		}
	case "revokedkeys":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.RevokedKeys = v
		}
	case "acceptenv":
		p.cfg.AcceptEnv = append(p.cfg.AcceptEnv, args...)
	case "setenv":
		if len(args) == 1 && strings.Contains(args[0], "=") {
			k, v, _ := strings.Cut(args[0], "=")
			p.cfg.SetEnv[k] = v
			break
		}
		if len(args) < 2 {
			return errors.New("setenv requires name and value")
		}
		p.cfg.SetEnv[args[0]] = strings.Join(args[1:], " ")
	case "subsystem":
		if len(args) < 2 {
			return errors.New("subsystem requires name and command")
		}
		p.cfg.Subsystems[args[0]] = strings.Join(args[1:], " ")
	case "forcecommand":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.ForceCommand = v
		}
	case "chrootdirectory":
		v, err := one()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.ChrootDirectory = v
		}
	case "clientaliveinterval":
		v, err := one()
		if err != nil {
			return err
		}
		d, err := parseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid ClientAliveInterval %q", v)
		}
		if p.first(k) {
			p.cfg.ClientAliveInterval = d
		}
	case "clientalivecountmax":
		v, err := one()
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid ClientAliveCountMax %q", v)
		}
		if p.first(k) {
			p.cfg.ClientAliveCountMax = n
		}
	case "tcpkeepalive":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.TCPKeepAlive = v
		}
	case "usedns":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if v {
			return fmt.Errorf("reverse-DNS matching is unavailable; set UseDNS to no")
		}
		if p.first(k) {
			p.cfg.UseDNS = false
		}
	case "compression":
		v, err := one()
		if err != nil {
			return err
		}
		switch strings.ToLower(v) {
		case "no":
			if p.first(k) {
				p.cfg.Compression = "no"
			}
		case "yes", "delayed":
			return fmt.Errorf("compression %s is not supported; only compression none is available", v)
		default:
			return fmt.Errorf("invalid Compression %q", v)
		}
	case "kexalgorithms":
		p.cfg.KexAlgorithms = splitComma(args)
	case "ciphers":
		p.cfg.Ciphers = splitComma(args)
	case "macs":
		p.cfg.MACs = splitComma(args)
	case "hostkeyalgorithms":
		p.cfg.HostKeyAlgorithms = splitComma(args)
	case "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes":
		p.cfg.PubkeyAcceptedAlgorithms = splitComma(args)
	case "requiredrsasize":
		v, err := one()
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1024 {
			return fmt.Errorf("invalid RequiredRSASize %q", v)
		}
		if p.first(k) {
			p.cfg.RequiredRSASize = n
		}
	case "casignaturealgorithms":
		if len(args) == 0 {
			return errors.New("CASignatureAlgorithms requires an argument")
		}
		if p.first(k) {
			p.cfg.CASignatureAlgorithms = splitComma(args)
		}
	case "rekeylimit", "fingerprinthash":
		if k == "rekeylimit" && len(args) > 0 {
			n, err := parseSize(args[0])
			if err != nil {
				return fmt.Errorf("invalid RekeyLimit %q", args[0])
			}
			if p.first(k) {
				p.cfg.RekeyLimit = n
			}
		}
	case "authenticationmethods":
		if len(args) == 0 {
			return errors.New("AuthenticationMethods requires an argument")
		}
		if !p.first(k) {
			break
		}
		alternatives := make([][]string, 0, len(args))
		for _, arg := range args {
			parts := strings.Split(arg, ",")
			alternative := make([]string, 0, len(parts))
			for _, part := range parts {
				method := strings.ToLower(strings.TrimSpace(part))
				switch method {
				case "publickey", "password", "keyboard-interactive":
					alternative = append(alternative, method)
				case "":
					return errors.New("AuthenticationMethods contains an empty method")
				default:
					return fmt.Errorf("unsupported AuthenticationMethods method %q", method)
				}
			}
			if len(alternative) == 0 {
				return errors.New("AuthenticationMethods contains an empty list")
			}
			alternatives = append(alternatives, alternative)
		}
		p.cfg.AuthenticationMethods = alternatives
	case "allowusers":
		p.cfg.AllowUsers = append(p.cfg.AllowUsers, args...)
	case "denyusers":
		p.cfg.DenyUsers = append(p.cfg.DenyUsers, args...)
	case "allowgroups":
		p.cfg.AllowGroups = append(p.cfg.AllowGroups, args...)
	case "denygroups":
		p.cfg.DenyGroups = append(p.cfg.DenyGroups, args...)
	case "usepam":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if p.first(k) {
			p.cfg.UsePAM = v
		}
	case "allowtcpforwarding", "allowagentforwarding", "allowstreamlocalforwarding",
		"x11forwarding", "x11displayoffset", "x11uselocalhost",
		"permitopen", "permitlisten", "gatewayports", "permittunnel",
		"disableforwarding", "refuseconnection", "showpatchlevel",
		"ipqos", "logverbose",
		"gssapiauthentication", "gssapicleanupcredentials",
		"gssapidelegatecredentials", "gssapistrictacceptorcheck",
		"hostbasedauthentication", "hostbasedacceptedalgorithms",
		"hostbasedusesnamefrompacketonly", "ignorerhosts",
		"ignoreuserknownhosts", "kerberosauthentication",
		"kerberosgetafstoken", "kerberosorlocalpasswd",
		"kerberosticketcleanup", "rhostsrsaauthentication",
		"rsaauthentication", "skeyauthentication", "streamlocalbindmask",
		"streamlocalbindunlink", "unusedconnectiontimeout", "modulifile":
		return nil
	default:
		return fmt.Errorf("unsupported configuration keyword %q", key)
	}
	if p.cfg.explicit == nil {
		p.cfg.explicit = map[string]bool{}
	}
	p.cfg.explicit[k] = true
	return nil
}

func splitComma(args []string) []string {
	var out []string
	for _, a := range args {
		for _, s := range strings.Split(a, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func parseMaxStartups(v string) (int, int, int, error) {
	parts := strings.Split(v, ":")
	if len(parts) > 3 {
		return 0, 0, 0, fmt.Errorf("invalid MaxStartups %q", v)
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 {
		return 0, 0, 0, fmt.Errorf("invalid MaxStartups %q", v)
	}
	rate := DefaultMaxStartupsRate
	full := DefaultMaxStartupsFull
	if len(parts) >= 2 {
		rate, err = strconv.Atoi(parts[1])
		if err != nil || rate < 0 || rate > 100 {
			return 0, 0, 0, fmt.Errorf("invalid MaxStartups %q", v)
		}
	}
	if len(parts) == 3 {
		full, err = strconv.Atoi(parts[2])
		if err != nil || full < 0 {
			return 0, 0, 0, fmt.Errorf("invalid MaxStartups %q", v)
		}
	}
	if start > full {
		return 0, 0, 0, fmt.Errorf("invalid MaxStartups %q: start must not exceed full", v)
	}
	return start, rate, full, nil
}

func splitListenAddress(v string) (string, int) {
	host, portStr, err := splitHostPortLoose(v)
	if err != nil {
		return v, 0
	}
	if portStr == "" {
		return host, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return v, 0
	}
	return host, port
}

func splitHostPortLoose(v string) (string, string, error) {
	if strings.HasPrefix(v, "[") {
		i := strings.LastIndex(v, "]")
		if i < 0 {
			return "", "", fmt.Errorf("missing ]")
		}
		host := v[1:i]
		rest := v[i+1:]
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("invalid address")
		}
		return host, rest[1:], nil
	}
	if strings.Count(v, ":") == 1 {
		parts := strings.SplitN(v, ":", 2)
		return parts[0], parts[1], nil
	}
	return v, "", nil
}

func stripComment(s string) string {
	var quote rune
	escaped := false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == '#' {
			return s[:i]
		}
	}
	return s
}

func splitFields(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return out, nil
}
