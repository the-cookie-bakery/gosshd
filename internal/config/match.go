package config

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
)

type MatchBlock struct {
	Users          []string
	Groups         []string
	Addresses      []string
	LocalAddresses []string
	LocalPorts     []string
	All            bool

	PasswordAuthentication       *bool
	PubkeyAuthentication         *bool
	KbdInteractiveAuthentication *bool
	PermitRootLogin              *string
	ForceCommand                 *string
	PermitTTY                    *bool
	ChrootDirectory              *string
	PermitUserRC                 *bool
	AcceptEnv                    []string
	AcceptEnvSet                 bool
	SetEnv                       map[string]string
	SetEnvSet                    bool
	AuthorizedKeysFile           []string
	AuthorizedKeysFileSet        bool
	MaxSessions                  *int
}

func (b MatchBlock) clone() MatchBlock {
	c := b
	c.Users = append([]string(nil), b.Users...)
	c.Groups = append([]string(nil), b.Groups...)
	c.Addresses = append([]string(nil), b.Addresses...)
	c.LocalAddresses = append([]string(nil), b.LocalAddresses...)
	c.LocalPorts = append([]string(nil), b.LocalPorts...)
	c.AcceptEnv = append([]string(nil), b.AcceptEnv...)
	c.AuthorizedKeysFile = append([]string(nil), b.AuthorizedKeysFile...)
	if b.SetEnv != nil {
		c.SetEnv = make(map[string]string, len(b.SetEnv))
		for k, v := range b.SetEnv {
			c.SetEnv[k] = v
		}
	}
	c.PasswordAuthentication = cloneBool(b.PasswordAuthentication)
	c.PubkeyAuthentication = cloneBool(b.PubkeyAuthentication)
	c.KbdInteractiveAuthentication = cloneBool(b.KbdInteractiveAuthentication)
	c.PermitTTY = cloneBool(b.PermitTTY)
	c.PermitUserRC = cloneBool(b.PermitUserRC)
	c.PermitRootLogin = cloneString(b.PermitRootLogin)
	c.ForceCommand = cloneString(b.ForceCommand)
	c.ChrootDirectory = cloneString(b.ChrootDirectory)
	c.MaxSessions = cloneInt(b.MaxSessions)
	return c
}

func cloneBool(v *bool) *bool {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func cloneString(v *string) *string {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func cloneInt(v *int) *int {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func (c *Config) Resolve(username string, groups []string, remote, local net.Addr) *Config {
	out := c.Clone()
	out.Matches = nil
	applied := map[string]bool{}
	global := c.explicit
	if global == nil {
		global = map[string]bool{}
	}
	for i := range c.Matches {
		block := &c.Matches[i]
		if !block.matches(username, groups, remote, local) {
			continue
		}
		block.apply(out, global, applied)
	}
	return out
}

func (b *MatchBlock) apply(out *Config, global, applied map[string]bool) {
	set := func(key string) bool {
		if global[key] || applied[key] {
			return false
		}
		applied[key] = true
		return true
	}
	if b.PasswordAuthentication != nil && set("passwordauthentication") {
		out.PasswordAuthentication = *b.PasswordAuthentication
	}
	if b.PubkeyAuthentication != nil && set("pubkeyauthentication") {
		out.PubkeyAuthentication = *b.PubkeyAuthentication
	}
	if b.KbdInteractiveAuthentication != nil && set("kbdinteractiveauthentication") {
		out.KbdInteractiveAuthentication = *b.KbdInteractiveAuthentication
	}
	if b.PermitRootLogin != nil && set("permitrootlogin") {
		out.PermitRootLogin = *b.PermitRootLogin
	}
	if b.ForceCommand != nil && set("forcecommand") {
		out.ForceCommand = *b.ForceCommand
	}
	if b.PermitTTY != nil && set("permittty") {
		out.PermitTTY = *b.PermitTTY
	}
	if b.ChrootDirectory != nil && set("chrootdirectory") {
		out.ChrootDirectory = *b.ChrootDirectory
	}
	if b.PermitUserRC != nil && set("permituserrc") {
		out.PermitUserRC = *b.PermitUserRC
	}
	if b.AcceptEnvSet && set("acceptenv") {
		out.AcceptEnv = append([]string(nil), b.AcceptEnv...)
	}
	if b.SetEnvSet && set("setenv") {
		out.SetEnv = make(map[string]string, len(b.SetEnv))
		for k, v := range b.SetEnv {
			out.SetEnv[k] = v
		}
	}
	if b.AuthorizedKeysFileSet && set("authorizedkeysfile") {
		out.AuthorizedKeysFile = append([]string(nil), b.AuthorizedKeysFile...)
	}
	if b.MaxSessions != nil && set("maxsessions") {
		out.MaxSessions = *b.MaxSessions
	}
}

func (b *MatchBlock) matches(username string, groups []string, remote, local net.Addr) bool {
	if b.All {
		return true
	}
	if len(b.Users) > 0 && !matchStringList(b.Users, username, matchGlob) {
		return false
	}
	if len(b.Groups) > 0 && !matchGroupList(b.Groups, groups) {
		return false
	}
	if len(b.Addresses) > 0 && !matchAddressList(b.Addresses, remote) {
		return false
	}
	if len(b.LocalAddresses) > 0 && !matchAddressList(b.LocalAddresses, local) {
		return false
	}
	if len(b.LocalPorts) > 0 && !matchPortList(b.LocalPorts, local) {
		return false
	}
	return true
}

func matchStringList(patterns []string, value string, match func(string, string) bool) bool {
	matched := false
	for _, raw := range patterns {
		negated := strings.HasPrefix(raw, "!")
		pattern := strings.TrimPrefix(raw, "!")
		if match(pattern, value) {
			if negated {
				return false
			}
			matched = true
		}
	}
	return matched
}

func matchGroupList(patterns, groups []string) bool {
	matched := false
	for _, raw := range patterns {
		negated := strings.HasPrefix(raw, "!")
		pattern := strings.TrimPrefix(raw, "!")
		for _, group := range groups {
			if matchGlob(pattern, group) {
				if negated {
					return false
				}
				matched = true
				break
			}
		}
	}
	return matched
}

func matchAddressList(patterns []string, addr net.Addr) bool {
	host := addrHost(addr)
	if host == "" {
		return false
	}
	return matchStringList(patterns, host, func(pattern, value string) bool {
		if strings.Contains(pattern, "/") {
			ip := net.ParseIP(value)
			_, network, err := net.ParseCIDR(pattern)
			return err == nil && ip != nil && network.Contains(ip)
		}
		if ip := net.ParseIP(pattern); ip != nil {
			return ip.Equal(net.ParseIP(value))
		}
		return matchGlob(pattern, value)
	})
}

func matchPortList(patterns []string, addr net.Addr) bool {
	// LocalPort is matched as a string so negation works uniformly.
	_, port, err := net.SplitHostPort(addrString(addr))
	if err != nil {
		return false
	}
	return matchStringList(patterns, port, func(pattern, value string) bool {
		return pattern == value
	})
}

func addrHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func matchGlob(pattern, value string) bool {
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}

func parseMatchCriteria(args []string) (MatchBlock, error) {
	var block MatchBlock
	if len(args) == 0 {
		return block, fmt.Errorf("match requires criteria")
	}
	criterion := ""
	seenAll := false
	for _, arg := range args {
		key := strings.ToLower(arg)
		switch key {
		case "user", "group", "address", "localaddress", "localport", "all":
			criterion = key
			if key == "all" {
				seenAll = true
			}
			continue
		}
		if criterion == "" {
			return block, fmt.Errorf("match value %q without a criterion", arg)
		}
		if criterion == "all" {
			return block, fmt.Errorf("match all does not accept values")
		}
		for _, value := range strings.Split(arg, ",") {
			value = strings.TrimSpace(value)
			if value == "" || value == "!" {
				return block, fmt.Errorf("empty Match value")
			}
			switch criterion {
			case "user":
				block.Users = append(block.Users, value)
			case "group":
				block.Groups = append(block.Groups, value)
			case "address":
				block.Addresses = append(block.Addresses, value)
			case "localaddress":
				block.LocalAddresses = append(block.LocalAddresses, value)
			case "localport":
				if _, err := strconv.Atoi(strings.TrimPrefix(value, "!")); err != nil {
					return block, fmt.Errorf("invalid LocalPort %q", value)
				}
				block.LocalPorts = append(block.LocalPorts, value)
			}
		}
	}
	if seenAll {
		if len(block.Users)+len(block.Groups)+len(block.Addresses)+len(block.LocalAddresses)+len(block.LocalPorts) > 0 {
			return block, fmt.Errorf("match all must be used alone")
		}
		block.All = true
	}
	if len(block.Users)+len(block.Groups)+len(block.Addresses)+len(block.LocalAddresses)+len(block.LocalPorts) == 0 && !block.All {
		return block, fmt.Errorf("match requires criteria")
	}
	return block, nil
}

func setMatchDirective(block *MatchBlock, seen map[string]bool, key string, args []string) error {
	k := strings.ToLower(key)
	if k == "challengeresponseauthentication" {
		k = "kbdinteractiveauthentication"
	}
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
	first := func() bool {
		if seen[k] {
			return false
		}
		seen[k] = true
		return true
	}

	switch k {
	case "passwordauthentication":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if first() {
			block.PasswordAuthentication = &v
		}
	case "pubkeyauthentication":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if first() {
			block.PubkeyAuthentication = &v
		}
	case "kbdinteractiveauthentication":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if first() {
			block.KbdInteractiveAuthentication = &v
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
			if first() {
				block.PermitRootLogin = &v
			}
		default:
			return fmt.Errorf("invalid PermitRootLogin %q", v)
		}
	case "forcecommand":
		v, err := one()
		if err != nil {
			return err
		}
		if first() {
			block.ForceCommand = &v
		}
	case "permittty":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if first() {
			block.PermitTTY = &v
		}
	case "chrootdirectory":
		v, err := one()
		if err != nil {
			return err
		}
		if first() {
			block.ChrootDirectory = &v
		}
	case "permituserrc":
		v, err := yesNo()
		if err != nil {
			return err
		}
		if first() {
			block.PermitUserRC = &v
		}
	case "acceptenv":
		if err := require(1); err != nil {
			return err
		}
		if first() {
			block.AcceptEnv = append([]string(nil), args...)
			block.AcceptEnvSet = true
		}
	case "setenv":
		values := map[string]string{}
		if len(args) == 1 && strings.Contains(args[0], "=") {
			name, value, _ := strings.Cut(args[0], "=")
			values[name] = value
		} else {
			if len(args) < 2 {
				return fmt.Errorf("setenv requires name and value")
			}
			values[args[0]] = strings.Join(args[1:], " ")
		}
		if first() {
			block.SetEnv = values
			block.SetEnvSet = true
		}
	case "authorizedkeysfile":
		if err := require(1); err != nil {
			return err
		}
		if first() {
			block.AuthorizedKeysFile = append([]string(nil), args...)
			block.AuthorizedKeysFileSet = true
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
		if first() {
			block.MaxSessions = &n
		}
	default:
		return fmt.Errorf("%s is not allowed inside Match", key)
	}
	return nil
}
