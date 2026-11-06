package nss

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	userCacheTTL    = 30 * time.Second
	userNegativeTTL = 10 * time.Second
	shadowCacheTTL  = 5 * time.Second
	groupCacheTTL   = 30 * time.Second
	getentTimeout   = 5 * time.Second
)

type User struct {
	Name   string
	UID    uint32
	GID    uint32
	Gecos  string
	Home   string
	Shell  string
	Groups []string
}

type Shadow struct {
	Name       string
	Hash       string
	LastChange int64
	Min        int64
	Max        int64
	Warn       int64
	Inact      int64
	Expire     int64
	Flag       int64
}

type Group struct {
	Name string
	GID  uint32
}

type cacheEntry[T any] struct {
	value   T
	found   bool
	expires time.Time
}

type ttlCache[T any] struct {
	mu          sync.Mutex
	ttl         time.Duration
	negativeTTL time.Duration
	entries     map[string]cacheEntry[T]
}

func newTTLCache[T any](ttl, negativeTTL time.Duration) *ttlCache[T] {
	return &ttlCache[T]{ttl: ttl, negativeTTL: negativeTTL, entries: map[string]cacheEntry[T]{}}
}

func (c *ttlCache[T]) get(key string) (T, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		var zero T
		return zero, false, false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, key)
		var zero T
		return zero, false, false
	}
	return e.value, e.found, true
}

func (c *ttlCache[T]) set(key string, value T, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.ttl
	if !found {
		ttl = c.negativeTTL
	}
	if len(c.entries) > 4096 {
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = cacheEntry[T]{value: value, found: found, expires: time.Now().Add(ttl)}
}

var (
	userCache   = newTTLCache[*User](userCacheTTL, userNegativeTTL)
	shadowCache = newTTLCache[*Shadow](shadowCacheTTL, shadowCacheTTL)
	groupCache  = newTTLCache[*Group](groupCacheTTL, userNegativeTTL)
)

func LookupUser(name string) (*User, error) {
	if !validName(name) {
		return nil, errors.New("invalid user name")
	}
	if cached, found, ok := userCache.get(name); ok {
		if !found {
			return nil, fmt.Errorf("user %q not found", name)
		}
		return cloneUser(cached), nil
	}
	u, err := lookupUserNSS(name)
	if err != nil {
		userCache.set(name, nil, false)
		return nil, err
	}
	u.Groups = lookupGroups(name, u.GID)
	userCache.set(name, u, true)
	return cloneUser(u), nil
}

func LookupShadow(name string) (*Shadow, error) {
	if !validName(name) {
		return nil, errors.New("invalid user name")
	}
	if cached, found, ok := shadowCache.get(name); ok {
		if !found {
			return nil, fmt.Errorf("shadow entry for %q not found", name)
		}
		return cloneShadow(cached), nil
	}
	s, err := lookupShadowNSS(name)
	if err != nil {
		shadowCache.set(name, nil, false)
		return nil, err
	}
	shadowCache.set(name, s, true)
	return cloneShadow(s), nil
}

func LookupGroup(name string) (*Group, error) {
	if !validName(name) {
		return nil, errors.New("invalid group name")
	}
	if cached, found, ok := groupCache.get(name); ok {
		if !found {
			return nil, fmt.Errorf("group %q not found", name)
		}
		clone := *cached
		return &clone, nil
	}
	g, err := lookupGroupNSS(name)
	if err != nil {
		groupCache.set(name, nil, false)
		return nil, err
	}
	groupCache.set(name, g, true)
	clone := *g
	return &clone, nil
}

func lookupUserNSS(name string) (*User, error) {
	if line, ok, err := getentLine("passwd", name); err == nil && ok {
		if u, err := parsePasswdLine(line); err == nil {
			return u, nil
		}
	}
	return lookupUserFile(name)
}

func lookupShadowNSS(name string) (*Shadow, error) {
	if line, ok, err := getentLine("shadow", name); err == nil && ok {
		if s, err := parseShadowLine(line); err == nil {
			return s, nil
		}
	}
	return lookupShadowFile(name)
}

func lookupGroupNSS(name string) (*Group, error) {
	if line, ok, err := getentLine("group", name); err == nil && ok {
		if g, err := parseGroupLine(line); err == nil {
			return g, nil
		}
	}
	return lookupGroupFile(name)
}

func getentLine(database, key string) (string, bool, error) {
	path := getentPath()
	if path == "" {
		return "", false, errors.New("getent not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), getentTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, database, key)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "", false, err
	}
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			return line, true, nil
		}
	}
	return "", false, nil
}

func getentPath() string {
	for _, path := range []string{"/usr/bin/getent", "/bin/getent"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func parsePasswdLine(line string) (*User, error) {
	parts := strings.SplitN(line, ":", 7)
	if len(parts) < 7 {
		return nil, errors.New("invalid passwd entry")
	}
	uid, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return nil, err
	}
	return &User{
		Name:  parts[0],
		UID:   uint32(uid),
		GID:   uint32(gid),
		Gecos: parts[4],
		Home:  parts[5],
		Shell: parts[6],
	}, nil
}

func parseShadowLine(line string) (*Shadow, error) {
	parts := strings.Split(line, ":")
	if len(parts) < 2 {
		return nil, errors.New("invalid shadow entry")
	}
	atoi := func(i int) int64 {
		if i >= len(parts) || parts[i] == "" {
			return -1
		}
		n, _ := strconv.ParseInt(parts[i], 10, 64)
		return n
	}
	return &Shadow{
		Name: parts[0], Hash: parts[1],
		LastChange: atoi(2), Min: atoi(3), Max: atoi(4),
		Warn: atoi(5), Inact: atoi(6), Expire: atoi(7), Flag: atoi(8),
	}, nil
}

func parseGroupLine(line string) (*Group, error) {
	parts := strings.SplitN(line, ":", 4)
	if len(parts) < 3 {
		return nil, errors.New("invalid group entry")
	}
	gid, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return nil, err
	}
	return &Group{Name: parts[0], GID: uint32(gid)}, nil
}

func lookupUserFile(name string) (*User, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		if u, e := user.Lookup(name); e == nil {
			uid, _ := strconv.ParseUint(u.Uid, 10, 32)
			gid, _ := strconv.ParseUint(u.Gid, 10, 32)
			return &User{Name: u.Username, UID: uint32(uid), GID: uint32(gid), Home: u.HomeDir, Gecos: u.Name}, nil
		}
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, name+":") {
			if u, err := parsePasswdLine(line); err == nil {
				return u, nil
			}
		}
	}
	return nil, fmt.Errorf("user %q not found", name)
}

func lookupShadowFile(name string) (*Shadow, error) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, name+":") {
			if s, err := parseShadowLine(line); err == nil {
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("shadow entry for %q not found", name)
}

func lookupGroupFile(name string) (*Group, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, name+":") {
			if g, err := parseGroupLine(line); err == nil {
				return g, nil
			}
		}
	}
	return nil, fmt.Errorf("group %q not found", name)
}

func lookupGroups(name string, gid uint32) []string {
	groups := []string{}
	f, err := os.Open("/etc/group")
	if err != nil {
		return groups
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		g, _ := strconv.ParseUint(parts[2], 10, 32)
		member := uint32(g) == gid
		if !member {
			for _, m := range strings.Split(parts[3], ",") {
				if m == name {
					member = true
					break
				}
			}
		}
		if member {
			groups = append(groups, parts[0])
		}
	}
	return groups
}

func validName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	if strings.HasPrefix(name, "-") {
		return false
	}
	for _, r := range name {
		if r == 0 || r == ':' || r == '\n' || r == '\r' || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func cloneUser(u *User) *User {
	if u == nil {
		return nil
	}
	clone := *u
	clone.Groups = append([]string(nil), u.Groups...)
	return &clone
}

func cloneShadow(s *Shadow) *Shadow {
	if s == nil {
		return nil
	}
	clone := *s
	return &clone
}
