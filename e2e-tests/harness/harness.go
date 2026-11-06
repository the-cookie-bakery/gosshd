package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type Options struct {
	Runtime       string
	Image         string
	Arch          string
	RepoRoot      string
	ArtifactsDir  string
	TestdataDir   string
	Timeout       time.Duration
	KeepOnFailure bool
	Env           map[string]string
}

type Harness struct {
	t       testing.TB
	opts    Options
	name    string
	started bool
	mu      sync.Mutex
}

type Result struct {
	Command  []string
	Output   string
	ExitCode int
}

func New(t testing.TB, opts Options) *Harness {
	t.Helper()
	if opts.Runtime == "" {
		opts.Runtime = "podman"
	}
	if opts.Arch == "" {
		opts.Arch = runtime.GOARCH
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Minute
	}
	if opts.RepoRoot == "" {
		opts.RepoRoot = findRepoRoot(t)
	}
	if opts.ArtifactsDir == "" {
		opts.ArtifactsDir = t.TempDir()
	}
	suffix := randomSuffix()
	return &Harness{t: t, opts: opts, name: fmt.Sprintf("gosshd-e2e-%d-%s", os.Getpid(), suffix)}
}

func (h *Harness) Options() Options {
	return h.opts
}

func (h *Harness) EnsureImage(ctx context.Context) error {
	if _, err := exec.LookPath(h.opts.Runtime); err != nil {
		return err
	}
	exists := exec.CommandContext(ctx, h.opts.Runtime, "image", "exists", h.opts.Image)
	if err := exists.Run(); err == nil {
		return nil
	}
	containerfile, err := h.containerfile()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, h.opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.opts.Runtime, "build", "-t", h.opts.Image, "-f", containerfile, filepath.Dir(containerfile))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (h *Harness) Start(ctx context.Context) error {
	if err := h.EnsureImage(ctx); err != nil {
		return err
	}
	args := []string{
		"run", "--detach", "--rm", "--init",
		"--name", h.name,
		"-v", h.opts.ArtifactsDir + ":/e2e:ro",
	}
	if h.opts.TestdataDir != "" {
		args = append(args, "-v", h.opts.TestdataDir+":/e2e-testdata:ro")
	}
	for k, v := range h.opts.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, h.opts.Image, "sleep", "infinity")
	cmd := exec.CommandContext(ctx, h.opts.Runtime, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		if strings.Contains(out.String(), "SELinux") {
			return h.startWithLabel(ctx)
		}
		return fmt.Errorf("podman run: %w: %s", err, strings.TrimSpace(out.String()))
	}
	h.mu.Lock()
	h.started = true
	h.mu.Unlock()
	h.t.Cleanup(func() { h.Close() })
	return nil
}

func (h *Harness) startWithLabel(ctx context.Context) error {
	args := []string{
		"run", "--detach", "--rm", "--init",
		"--security-opt", "label=disable",
		"--name", h.name,
		"-v", h.opts.ArtifactsDir + ":/e2e:ro",
	}
	if h.opts.TestdataDir != "" {
		args = append(args, "-v", h.opts.TestdataDir+":/e2e-testdata:ro")
	}
	for k, v := range h.opts.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, h.opts.Image, "sleep", "infinity")
	cmd := exec.CommandContext(ctx, h.opts.Runtime, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	h.mu.Lock()
	h.started = true
	h.mu.Unlock()
	h.t.Cleanup(func() { h.Close() })
	return nil
}

func (h *Harness) Exec(ctx context.Context, args ...string) (Result, error) {
	cmdArgs := append([]string{"exec", "-i", h.name}, args...)
	return h.run(ctx, cmdArgs...)
}

func (h *Harness) RunTestBinary(ctx context.Context, name string, args ...string) (Result, error) {
	cmdArgs := append([]string{"/e2e/" + name}, args...)
	return h.Exec(ctx, cmdArgs...)
}

func (h *Harness) Logs(ctx context.Context) string {
	res, _ := h.run(ctx, "logs", h.name)
	return res.Output
}

func (h *Harness) Diagnostics(ctx context.Context) string {
	var b strings.Builder
	b.WriteString("=== podman inspect ===\n")
	if res, err := h.run(ctx, "inspect", h.name); err == nil {
		b.WriteString(res.Output)
	}
	b.WriteString("\n=== podman logs ===\n")
	b.WriteString(h.Logs(ctx))
	b.WriteString("\n=== artifacts ===\n")
	b.WriteString(h.opts.ArtifactsDir)
	b.WriteString("\n")
	return b.String()
}

func (h *Harness) Close() {
	h.mu.Lock()
	started := h.started
	h.started = false
	h.mu.Unlock()
	if !started {
		return
	}
	if h.opts.KeepOnFailure && h.t.Failed() {
		h.t.Logf("keeping container %s", h.name)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, h.opts.Runtime, "rm", "-f", h.name).Run()
}

func (h *Harness) run(ctx context.Context, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, h.opts.Runtime, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	res := Result{Command: append([]string{h.opts.Runtime}, args...), Output: out.String()}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		}
	}
	return res, err
}

func (h *Harness) containerfile() (string, error) {
	name := "debian"
	switch {
	case strings.Contains(h.opts.Image, "ubuntu"):
		name = "ubuntu"
	case strings.Contains(h.opts.Image, "fedora"):
		name = "fedora"
	}
	p := filepath.Join(h.opts.RepoRoot, "e2e-tests", "images", name, "Containerfile")
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

type Artifacts struct {
	Dir    string
	Gosshd string
	Suites map[string]string
}

func BuildArtifacts(t testing.TB, opts Options, suites []string) Artifacts {
	t.Helper()
	if opts.RepoRoot == "" {
		opts.RepoRoot = findRepoRoot(t)
	}
	if opts.Arch == "" {
		opts.Arch = runtime.GOARCH
	}
	if opts.ArtifactsDir == "" {
		opts.ArtifactsDir = t.TempDir()
	}
	if err := os.MkdirAll(opts.ArtifactsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+opts.Arch)
	gosshd := filepath.Join(opts.ArtifactsDir, "gosshd")
	build := exec.Command("go", "build", "-trimpath", "-o", gosshd, "./cmd/gosshd")
	build.Dir = opts.RepoRoot
	build.Env = env
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build gosshd: %v", err)
	}
	out := Artifacts{Dir: opts.ArtifactsDir, Gosshd: gosshd, Suites: map[string]string{}}
	for _, suite := range suites {
		bin := filepath.Join(opts.ArtifactsDir, suite+".test")
		cmd := exec.Command("go", "test", "-c", "-tags=e2e", "-o", bin, "./e2e-tests/suites/"+suite)
		cmd.Dir = opts.RepoRoot
		cmd.Env = env
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("build suite %s: %v", suite, err)
		}
		out.Suites[suite] = bin
	}
	return out
}

func findRepoRoot(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatal("could not find repository root")
	return ""
}

func randomSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func PodmanAvailable() bool {
	_, err := exec.LookPath("podman")
	return err == nil
}

func RequirePodman(t testing.TB) {
	t.Helper()
	if PodmanAvailable() {
		return
	}
	if os.Getenv("GOSSHD_E2E_REQUIRE") == "1" {
		t.Fatal("podman is required but not available")
	}
	t.Skip("podman is not available")
}

var ErrNotStarted = errors.New("container not started")
