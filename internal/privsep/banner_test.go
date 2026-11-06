package privsep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBanner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "banner")
	if err := os.WriteFile(path, []byte("welcome\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadBanner(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "welcome\n" {
		t.Fatalf("banner=%q", got)
	}
	if got, err := loadBanner(""); err != nil || got != "" {
		t.Fatalf("empty banner got=%q err=%v", got, err)
	}
	if _, err := loadBanner(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got %v", err)
	}

	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxBannerSize+10)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = loadBanner(large)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxBannerSize {
		t.Fatalf("large banner length=%d want %d", len(got), maxBannerSize)
	}
}
