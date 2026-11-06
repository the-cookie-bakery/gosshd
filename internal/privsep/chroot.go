package privsep

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cookiengineer/gosshd/internal/auth"
)

func resolveChroot(spec string, perms *auth.Permissions) (string, error) {
	if spec == "" {
		return "", nil
	}
	expanded, err := expandChrootTokens(spec, perms)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(expanded) {
		return "", fmt.Errorf("chroot directory must be absolute")
	}
	clean := filepath.Clean(expanded)
	for dir := clean; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return "", fmt.Errorf("chroot %s: %w", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("chroot component %s is a symlink", dir)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("chroot component %s is not a directory", dir)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return "", fmt.Errorf("chroot component %s is not owned by root", dir)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("chroot component %s is group or world writable", dir)
		}
		if dir == "/" {
			break
		}
	}
	return clean, nil
}

func expandChrootTokens(spec string, perms *auth.Permissions) (string, error) {
	var b strings.Builder
	for i := 0; i < len(spec); i++ {
		if spec[i] != '%' {
			b.WriteByte(spec[i])
			continue
		}
		i++
		if i >= len(spec) {
			return "", fmt.Errorf("trailing %% in chroot directory")
		}
		switch spec[i] {
		case '%':
			b.WriteByte('%')
		case 'h':
			b.WriteString(perms.Home)
		case 'u':
			b.WriteString(perms.Username)
		case 'U':
			b.WriteString(strconv.FormatUint(uint64(perms.UID), 10))
		default:
			return "", fmt.Errorf("unsupported chroot token %%%c", spec[i])
		}
	}
	return b.String(), nil
}
