package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cookiengineer/gosshd/internal/auth"
	"github.com/cookiengineer/gosshd/internal/config"
	"github.com/cookiengineer/gosshd/internal/crypto"
	"github.com/cookiengineer/gosshd/internal/privsep"
	"github.com/cookiengineer/gosshd/internal/session"
)

const version = "0.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--internal-worker":
			if err := privsep.RunWorker(); err != nil {
				log.Fatal(err)
			}
			return
		case "--internal-session":
			raw, err := base64.StdEncoding.DecodeString(os.Getenv("GOSSHD_SESSION_SPEC"))
			if err != nil {
				log.Fatal(err)
			}
			var spec privsep.SessionSpec
			if err := json.Unmarshal(raw, &spec); err != nil {
				log.Fatal(err)
			}
			if err := session.Run(&spec); err != nil {
				log.Fatal(err)
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
	_ = stderrLog
	if *showVersion {
		fmt.Printf("gosshd %s\n", version)
		return 0
	}
	if *inetd {
		fmt.Fprintln(os.Stderr, "inetd mode is not implemented")
		return 1
	}
	cfg, err := config.ParseFile(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *port != 0 {
		cfg.Port = *port
	}
	if *hostKey != "" {
		cfg.HostKeys = append(cfg.HostKeys, *hostKey)
	}
	if *option != "" {
		if err := config.ParseOption(cfg, *option); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	if *ipv4 && *ipv6 {
		fmt.Fprintln(os.Stderr, "-4 and -6 are mutually exclusive")
		return 1
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
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		cfg.LoginGraceTime = d
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cfg.UsePAM {
		fmt.Fprintln(os.Stderr, "UsePAM is not supported by this build; set UsePAM no")
		return 1
	}
	if cfg.AuthorizedKeysCommand != "" {
		log.Printf("warning: AuthorizedKeysCommand is configured but is not executed by this build")
	}
	if err := crypto.Apply(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
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
		fmt.Fprintln(os.Stderr, err)
		return 1
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
	authenticator, err := auth.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	monitor := privsep.NewMonitor(cfg, authenticator, signers)
	if err := monitor.Listen(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cfg.PidFile != "" {
		_ = os.WriteFile(cfg.PidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
		defer os.Remove(cfg.PidFile)
	}
	if err := privsep.DropMonitorCapabilities(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, addr := range monitor.Addrs() {
		log.Printf("listening on %s", addr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := monitor.Serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
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
