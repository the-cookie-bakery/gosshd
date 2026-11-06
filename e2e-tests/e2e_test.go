//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cookiengineer/gosshd/e2e-tests/harness"
)

func TestE2E(t *testing.T) {
	harness.RequirePodman(t)
	root := repoRoot(t)
	images := os.Getenv("GOSSHD_E2E_IMAGES")
	if images == "" {
		images = "debian,ubuntu,fedora"
	}
	suites := os.Getenv("GOSSHD_E2E_SUITES")
	if suites == "" {
		suites = "smoke,auth,privsep,config,cert,interop"
	}
	suiteNames := splitList(suites)
	artifacts := harness.BuildArtifacts(t, harness.Options{RepoRoot: root}, suiteNames)
	for _, imageName := range strings.Split(images, ",") {
		imageName = strings.TrimSpace(imageName)
		if imageName == "" {
			continue
		}
		image := imageName
		if !strings.Contains(image, ":") {
			image = "gosshd-e2e-" + imageName + ":local"
		}
		for _, suite := range suiteNames {
			t.Run(imageName+"/"+suite, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
				defer cancel()
				h := harness.New(t, harness.Options{
					Image:         image,
					RepoRoot:      root,
					ArtifactsDir:  artifacts.Dir,
					TestdataDir:   root + "/e2e-tests/testdata",
					KeepOnFailure: os.Getenv("GOSSHD_E2E_KEEP") == "1",
					Env: map[string]string{
						"GOSSHD_BIN":      "/e2e/gosshd",
						"GOSSHD_TESTDATA": "/e2e-testdata",
					},
				})
				if err := h.Start(ctx); err != nil {
					t.Fatal(err)
				}
				res, err := h.RunTestBinary(ctx, suite+".test", "-test.v", "-test.timeout=10m")
				if err != nil {
					t.Log(h.Diagnostics(ctx))
					t.Fatalf("suite %s failed: %v\n%s", suite, err, res.Output)
				}
				t.Log(res.Output)
			})
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/" && dir != "."; dir = parent(dir) {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
	}
	t.Fatal("repo root not found")
	return ""
}

func splitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parent(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}
