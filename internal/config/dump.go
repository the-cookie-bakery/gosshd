package config

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (c *Config) WriteEffective(w io.Writer) error {
	b := bufio.NewWriter(w)
	line := func(key string, values ...string) {
		fmt.Fprint(b, key)
		for _, value := range values {
			fmt.Fprintf(b, " %s", value)
		}
		fmt.Fprintln(b)
	}
	linef := func(key, format string, args ...any) {
		fmt.Fprintf(b, "%s %s\n", key, fmt.Sprintf(format, args...))
	}
	yesNo := func(v bool) string {
		if v {
			return "yes"
		}
		return "no"
	}

	linef("port", "%d", c.Port)
	line("addressfamily", strings.ToLower(c.AddressFamily))
	addrs, err := c.Listeners()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		line("listenaddress", addr)
	}
	for _, path := range c.HostKeys {
		line("hostkey", path)
	}
	for _, path := range c.HostCertificates {
		line("hostcertificate", path)
	}
	if c.PidFile != "" {
		line("pidfile", c.PidFile)
	}
	line("loglevel", strings.ToLower(c.LogLevel))
	line("syslogfacility", strings.ToLower(c.SyslogFacility))
	linef("maxstartups", "%d:%d:%d", c.MaxStartups, c.MaxStartupsRate, c.MaxStartupsFull)
	line("usedns", yesNo(c.UseDNS))
	line("compression", strings.ToLower(c.Compression))
	linef("maxauthtries", "%d", c.MaxAuthTries)
	linef("maxsessions", "%d", c.MaxSessions)
	linef("logingracetime", "%d", int64(c.LoginGraceTime/time.Second))
	line("passwordauthentication", yesNo(c.PasswordAuthentication))
	line("pubkeyauthentication", yesNo(c.PubkeyAuthentication))
	line("kbdinteractiveauthentication", yesNo(c.KbdInteractiveAuthentication))
	line("permitemptypasswords", yesNo(c.PermitEmptyPasswords))
	line("permitrootlogin", c.PermitRootLogin)
	line("permittty", yesNo(c.PermitTTY))
	line("strictmodes", yesNo(c.StrictModes))
	line("permituserenvironment", c.PermitUserEnvironment)
	line("permituserrc", yesNo(c.PermitUserRC))
	line("printmotd", yesNo(c.PrintMotd))
	line("printlastlog", yesNo(c.PrintLastLog))
	if c.Banner != "" {
		line("banner", c.Banner)
	}
	line("authorizedkeysfile", c.AuthorizedKeysFile...)
	if len(c.AuthorizedKeysCommand) > 0 {
		line("authorizedkeyscommand", c.AuthorizedKeysCommand...)
	}
	if c.AuthorizedKeysCommandUser != "" {
		line("authorizedkeyscommanduser", c.AuthorizedKeysCommandUser)
	}
	if len(c.AuthorizedPrincipalsCommand) > 0 {
		line("authorizedprincipalscommand", c.AuthorizedPrincipalsCommand...)
	}
	if c.AuthorizedPrincipalsCommandUser != "" {
		line("authorizedprincipalscommanduser", c.AuthorizedPrincipalsCommandUser)
	}
	for _, path := range c.TrustedUserCAKeys {
		line("trustedusercakeys", path)
	}
	if c.AuthorizedPrincipalsFile != "" {
		line("authorizedprincipalsfile", c.AuthorizedPrincipalsFile)
	}
	if c.RevokedKeys != "" {
		line("revokedkeys", c.RevokedKeys)
	}
	if len(c.AcceptEnv) > 0 {
		line("acceptenv", c.AcceptEnv...)
	}
	for _, key := range sortedKeys(c.SetEnv) {
		line("setenv", key+"="+c.SetEnv[key])
	}
	for _, name := range sortedKeys(c.Subsystems) {
		line("subsystem", name, c.Subsystems[name])
	}
	if c.ForceCommand != "" {
		line("forcecommand", c.ForceCommand)
	}
	if c.ChrootDirectory != "" {
		line("chrootdirectory", c.ChrootDirectory)
	}
	linef("clientaliveinterval", "%d", int64(c.ClientAliveInterval/time.Second))
	linef("clientalivecountmax", "%d", c.ClientAliveCountMax)
	line("tcpkeepalive", yesNo(c.TCPKeepAlive))
	line("kexalgorithms", c.KexAlgorithms...)
	line("ciphers", c.Ciphers...)
	line("macs", c.MACs...)
	line("hostkeyalgorithms", c.HostKeyAlgorithms...)
	line("pubkeyacceptedalgorithms", c.PubkeyAcceptedAlgorithms...)
	line("casignaturealgorithms", c.CASignatureAlgorithms...)
	linef("requiredrsasize", "%d", c.RequiredRSASize)
	if c.RekeyLimit > 0 {
		line("rekeylimit", strconv.FormatInt(c.RekeyLimit, 10))
	}
	if len(c.AuthenticationMethods) > 0 {
		alternatives := make([]string, 0, len(c.AuthenticationMethods))
		for _, methods := range c.AuthenticationMethods {
			alternatives = append(alternatives, strings.Join(methods, ","))
		}
		line("authenticationmethods", alternatives...)
	}
	if len(c.AllowUsers) > 0 {
		line("allowusers", c.AllowUsers...)
	}
	if len(c.DenyUsers) > 0 {
		line("denyusers", c.DenyUsers...)
	}
	if len(c.AllowGroups) > 0 {
		line("allowgroups", c.AllowGroups...)
	}
	if len(c.DenyGroups) > 0 {
		line("denygroups", c.DenyGroups...)
	}
	line("usepam", yesNo(c.UsePAM))
	return b.Flush()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
