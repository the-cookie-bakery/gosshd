package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"

	"github.com/cookiengineer/gosshd/internal/privsep"
)

type readWriteCloser struct {
	io.Reader
	io.Writer
}

func (r readWriteCloser) Close() error {
	return nil
}

func Run(spec *privsep.SessionSpec) error {
	_ = unix.Umask(0o077)
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 4096, Max: 4096})
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if err := applySessionSandbox(spec); err != nil {
		return fmt.Errorf("session sandbox: %w", err)
	}
	if spec.Chroot != "" {
		if err := syscall.Chroot(spec.Chroot); err != nil {
			return fmt.Errorf("chroot: %w", err)
		}
		if err := os.Chdir("/"); err != nil {
			return err
		}
	}
	groups := make([]int, 0, len(spec.Groups)+1)
	groups = append(groups, int(spec.GID))
	for _, g := range spec.Groups {
		if g != spec.GID {
			groups = append(groups, int(g))
		}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(int(spec.GID)); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(int(spec.UID)); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	env := spec.Env
	if spec.Command == "" || len(env) == 0 {
		env = ensureEnv(env)
	}
	if err := os.Chdir(spec.Home); err != nil {
		_ = os.Chdir("/")
	}
	if spec.Pty {
		_ = applyTerminalModes(0, spec.Modes)
	}
	if spec.Command == "" && spec.Subsystem == "" {
		writeLoginInfo(spec)
	}
	if !spec.NoUserRC && spec.Subsystem == "" {
		runUserRC(spec)
	}
	if spec.Subsystem != "" {
		opts, internal, err := parseInternalSFTP(spec.SubsystemCommand)
		if err != nil {
			return err
		}
		if internal {
			startDir := opts.StartDir
			if startDir == "" {
				startDir = mustGetwd()
			}
			serverOpts := []sftp.ServerOption{sftp.WithServerWorkingDirectory(startDir)}
			if opts.ReadOnly {
				serverOpts = append(serverOpts, sftp.ReadOnly())
			}
			rwc := readWriteCloser{Reader: os.Stdin, Writer: os.Stdout}
			srv, err := sftp.NewServer(rwc, serverOpts...)
			if err != nil {
				return err
			}
			err = srv.Serve()
			_ = srv.Close()
			return err
		}
		return execShell("/bin/sh", []string{"sh", "-c", spec.SubsystemCommand}, env)
	}
	switch {
	case spec.Command != "":
		shell := spec.Shell
		if shell == "" {
			shell = "/bin/sh"
		}
		return execShell(shell, []string{filepath.Base(shell), "-c", spec.Command}, env)
	default:
		shell := spec.Shell
		if shell == "" {
			shell = "/bin/sh"
		}
		argv0 := "-" + filepath.Base(shell)
		return execShell(shell, []string{argv0}, env)
	}
}

func writeLoginInfo(spec *privsep.SessionSpec) {
	if spec.LastLog != "" {
		_, _ = io.WriteString(os.Stdout, spec.LastLog)
	}
	if spec.Motd != "" {
		_, _ = io.WriteString(os.Stdout, spec.Motd)
		if !strings.HasSuffix(spec.Motd, "\n") {
			_, _ = io.WriteString(os.Stdout, "\n")
		}
	}
}

func runUserRC(spec *privsep.SessionSpec) {
	rc := filepath.Join(spec.Home, ".ssh", "rc")
	if _, err := os.Stat(rc); err != nil {
		rc = "/etc/ssh/sshrc"
		if _, err := os.Stat(rc); err != nil {
			return
		}
	}
	shell := spec.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-c", rc)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = spec.Env
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "rc: %v\n", err)
	}
}

func execShell(path string, argv []string, env []string) error {
	if path == "" {
		return errors.New("empty shell")
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return syscall.Exec(path, argv, env)
}

func ensureEnv(env []string) []string {
	hasPath := false
	hasHome := false
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
		}
		if strings.HasPrefix(e, "HOME=") {
			hasHome = true
		}
	}
	if !hasPath {
		env = append(env, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	if !hasHome {
		if h, err := os.UserHomeDir(); err == nil {
			env = append(env, "HOME="+h)
		}
	}
	return env
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "/"
	}
	return wd
}
