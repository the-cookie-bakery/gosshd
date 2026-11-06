package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cookiengineer/gosshd/internal/auth"
	"github.com/cookiengineer/gosshd/internal/config"
	"github.com/cookiengineer/gosshd/internal/crypto"
	"github.com/cookiengineer/gosshd/internal/logging"
	"github.com/cookiengineer/gosshd/internal/privsep"
	"github.com/cookiengineer/gosshd/internal/session"
)

const version = "0.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--internal-worker":
			if err := privsep.RunWorker(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "--internal-session":
			raw, err := base64.StdEncoding.DecodeString(os.Getenv("GOSSHD_SESSION_SPEC"))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			var spec privsep.SessionSpec
			if err := json.Unmarshal(raw, &spec); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := session.Run(&spec); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("gosshd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("f", "/etc/ssh/sshd_config", "configuration file")
	testConfig := fs.Bool("t", false, "test configuration")
	dumpConfig := fs.Bool("T", false, "dump effective configuration")
	foreground := fs.Bool("D", false, "do not detach")
	port := fs.Int("p", 0, "port")
	hostKey := fs.String("h", "", "host key file")
	option := fs.String("o", "", "configuration option")
	stderrLog := fs.Bool("e", false, "log to stderr")
	inetd := fs.Bool("i", false, "inetd mode")
	ipv4 := fs.Bool("4", false, "IPv4 only")
	ipv6 := fs.Bool("6", false, "IPv6 only")
	grace := fs.String("g", "", "login grace time")
	showVersion := fs.Bool("V", false, "version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_ = foreground
	if *showVersion {
		fmt.Printf("gosshd %s\n", version)
		return 0
	}

	load := func() (*config.Config, []ssh.Signer, *auth.Authenticator, error) {
		cfg, err := config.ParseFile(*configPath)
		if err != nil {
			return nil, nil, nil, err
		}
		if *port != 0 {
			cfg.Port = *port
		}
		if *hostKey != "" {
			cfg.HostKeys = append(cfg.HostKeys, *hostKey)
		}
		if *option != "" {
			if err := config.ParseOption(cfg, *option); err != nil {
				return nil, nil, nil, err
			}
		}
		if *ipv4 && *ipv6 {
			return nil, nil, nil, fmt.Errorf("-4 and -6 are mutually exclusive")
		}
		if *ipv4 {
			cfg.AddressFamily = "inet"
		}
		if *ipv6 {
			cfg.AddressFamily = "inet6"
		}
		if *grace != "" {
			d, err := parseGrace(*grace)
			if err != nil {
				return nil, nil, nil, err
			}
			cfg.LoginGraceTime = d
		}
		if err := cfg.Validate(); err != nil {
			return nil, nil, nil, err
		}
		if cfg.UsePAM {
			return nil, nil, nil, fmt.Errorf("UsePAM is not supported by this build; set UsePAM no")
		}
		if err := crypto.Apply(cfg); err != nil {
			return nil, nil, nil, err
		}
		if len(cfg.HostKeys) == 0 {
			for _, p := range []string{
				"/etc/ssh/ssh_host_ed25519_key",
				"/etc/ssh/ssh_host_ecdsa_key",
				"/etc/ssh/ssh_host_rsa_key",
			} {
				if _, err := os.Stat(p); err == nil {
					cfg.HostKeys = append(cfg.HostKeys, p)
				}
			}
		}
		signers, err := crypto.LoadHostSigners(cfg.HostKeys, cfg.HostCertificates, cfg.HostKeyAlgorithms, cfg.RequiredRSASize)
		if err != nil {
			return nil, nil, nil, err
		}
		authenticator, err := auth.New(cfg)
		if err != nil {
			return nil, nil, nil, err
		}
		return cfg, signers, authenticator, nil
	}

	cfg, signers, authenticator, err := load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !*testConfig && !*dumpConfig {
		logging.Configure(cfg.LogLevel, cfg.SyslogFacility, *stderrLog)
	}
	if *testConfig || *dumpConfig {
		if *dumpConfig {
			raw, _ := json.MarshalIndent(cfg, "", "  ")
			fmt.Println(string(raw))
		} else {
			fmt.Println("configuration OK")
		}
		return 0
	}

	if err := session.CheckSandbox(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	monitor := privsep.NewMonitor(cfg, authenticator, signers)
	if !*inetd {
		listeners, activated, err := systemdListeners()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if activated {
			monitor.SetListeners(listeners)
		} else if err := monitor.Listen(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if cfg.PidFile != "" {
			_ = os.WriteFile(cfg.PidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
			defer os.Remove(cfg.PidFile)
		}
	}
	if err := privsep.DropMonitorCapabilities(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *inetd {
		return serveInetd(monitor)
	}
	for _, addr := range monitor.Addrs() {
		logging.Infof("listening on %s", addr)
	}

	currentCfg := cfg
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for range hup {
			newCfg, _, newAuthenticator, err := load()
			if err != nil {
				logging.Errorf("reload failed: %v", err)
				continue
			}
			if err := reloadCompatible(currentCfg, newCfg); err != nil {
				logging.Errorf("reload rejected: %v", err)
				continue
			}
			logging.Configure(newCfg.LogLevel, newCfg.SyslogFacility, *stderrLog)
			monitor.Reload(newCfg, newAuthenticator)
			currentCfg = newCfg
			logging.Infof("configuration reloaded")
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := monitor.Serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func reloadCompatible(old, next *config.Config) error {
	if old.Port != next.Port {
		return fmt.Errorf("reload: Port changes require a restart")
	}
	if old.AddressFamily != next.AddressFamily {
		return fmt.Errorf("reload: AddressFamily changes require a restart")
	}
	if !reflect.DeepEqual(old.ListenAddresses, next.ListenAddresses) {
		return fmt.Errorf("reload: ListenAddress changes require a restart")
	}
	if !reflect.DeepEqual(old.HostKeys, next.HostKeys) {
		return fmt.Errorf("reload: HostKey changes require a restart")
	}
	if !reflect.DeepEqual(old.HostCertificates, next.HostCertificates) {
		return fmt.Errorf("reload: HostCertificate changes require a restart")
	}
	if !reflect.DeepEqual(old.HostKeyAlgorithms, next.HostKeyAlgorithms) {
		return fmt.Errorf("reload: HostKeyAlgorithms changes require a restart")
	}
	if old.RequiredRSASize != next.RequiredRSASize {
		return fmt.Errorf("reload: RequiredRSASize changes require a restart")
	}
	if old.MaxStartups != next.MaxStartups {
		return fmt.Errorf("reload: MaxStartups changes require a restart")
	}
	if old.MaxStartupsRate != next.MaxStartupsRate || old.MaxStartupsFull != next.MaxStartupsFull {
		return fmt.Errorf("reload: MaxStartups changes require a restart")
	}
	return nil
}

func serveInetd(monitor *privsep.Monitor) int {
	file := os.NewFile(0, "stdin")
	if file == nil {
		fmt.Fprintln(os.Stderr, "inetd mode: stdin is not available")
		return 1
	}
	conn, err := net.FileConn(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inetd mode:", err)
		return 1
	}
	defer conn.Close()
	monitor.ServeConn(conn)
	return 0
}

func systemdListeners() ([]net.Listener, bool, error) {
	pidText := os.Getenv("LISTEN_PID")
	fdsText := os.Getenv("LISTEN_FDS")
	if pidText == "" || fdsText == "" {
		return nil, false, nil
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid != os.Getpid() {
		return nil, false, nil
	}
	n, err := strconv.Atoi(fdsText)
	if err != nil || n <= 0 {
		return nil, false, nil
	}
	listeners := make([]net.Listener, 0, n)
	for i := 0; i < n; i++ {
		fd := 3 + i
		file := os.NewFile(uintptr(fd), fmt.Sprintf("systemd-fd-%d", fd))
		if file == nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, true, fmt.Errorf("invalid systemd fd %d", fd)
		}
		listener, err := net.FileListener(file)
		file.Close()
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, true, err
		}
		listeners = append(listeners, listener)
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	return listeners, true, nil
}

func parseGrace(v string) (time.Duration, error) {
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}
