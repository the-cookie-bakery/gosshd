package nss

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
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

type passwdC struct {
	Name   *byte
	Passwd *byte
	UID    uint32
	GID    uint32
	Gecos  *byte
	Dir    *byte
	Shell  *byte
}

type spwdC struct {
	Name       *byte
	Passwd     *byte
	LastChange int64
	Min        int64
	Max        int64
	Warn       int64
	Inact      int64
	Expire     int64
	Flag       int64
}

var (
	libcOnce sync.Once
	libcErr  error
	libcMu   sync.Mutex
	getpwnam func(string) unsafe.Pointer
	getspnam func(string) unsafe.Pointer
)

func loadLibc() {
	libcOnce.Do(func() {
		var h uintptr
		for _, name := range []string{"libc.so.6", "libc.so", "libc.musl-x86_64.so.1", "libc.musl-aarch64.so.1"} {
			if v, err := purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL); err == nil {
				h = v
				break
			}
		}
		if h == 0 {
			libcErr = errors.New("could not load libc")
			return
		}
		if addr, err := purego.Dlsym(h, "getpwnam"); err == nil && addr != 0 {
			purego.RegisterFunc(&getpwnam, addr)
		}
		if addr, err := purego.Dlsym(h, "getspnam"); err == nil && addr != 0 {
			purego.RegisterFunc(&getspnam, addr)
		}
	})
}

func LookupUser(name string) (*User, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return nil, errors.New("invalid user name")
	}
	loadLibc()
	if libcErr == nil && getpwnam != nil {
		if u, err := lookupUserLibc(name); err == nil {
			u.Groups = lookupGroups(name, u.GID)
			return u, nil
		}
	}
	u, err := lookupUserFile(name)
	if err != nil {
		return nil, err
	}
	u.Groups = lookupGroups(name, u.GID)
	return u, nil
}

func LookupShadow(name string) (*Shadow, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return nil, errors.New("invalid user name")
	}
	loadLibc()
	if libcErr == nil && getspnam != nil {
		if s, err := lookupShadowLibc(name); err == nil {
			return s, nil
		}
	}
	return lookupShadowFile(name)
}

func lookupUserLibc(name string) (*User, error) {
	libcMu.Lock()
	defer libcMu.Unlock()
	r := getpwnam(name)
	if r == nil {
		return nil, fmt.Errorf("user %q not found", name)
	}
	v := (*passwdC)(r)
	return &User{
		Name:  unix.BytePtrToString(v.Name),
		UID:   v.UID,
		GID:   v.GID,
		Gecos: unix.BytePtrToString(v.Gecos),
		Home:  unix.BytePtrToString(v.Dir),
		Shell: unix.BytePtrToString(v.Shell),
	}, nil
}

func lookupShadowLibc(name string) (*Shadow, error) {
	libcMu.Lock()
	defer libcMu.Unlock()
	r := getspnam(name)
	if r == nil {
		return nil, fmt.Errorf("shadow entry for %q not found", name)
	}
	v := (*spwdC)(r)
	return &Shadow{
		Name:       unix.BytePtrToString(v.Name),
		Hash:       unix.BytePtrToString(v.Passwd),
		LastChange: v.LastChange,
		Min:        v.Min,
		Max:        v.Max,
		Warn:       v.Warn,
		Inact:      v.Inact,
		Expire:     v.Expire,
		Flag:       v.Flag,
	}, nil
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
		parts := strings.Split(line, ":")
		if len(parts) < 7 || parts[0] != name {
			continue
		}
		uid, _ := strconv.ParseUint(parts[2], 10, 32)
		gid, _ := strconv.ParseUint(parts[3], 10, 32)
		return &User{Name: parts[0], UID: uint32(uid), GID: uint32(gid), Gecos: parts[4], Home: parts[5], Shell: parts[6]}, nil
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
		parts := strings.Split(line, ":")
		if len(parts) < 2 || parts[0] != name {
			continue
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
	return nil, fmt.Errorf("shadow entry for %q not found", name)
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

type Group struct {
	Name string
	GID  uint32
}

func LookupGroup(name string) (*Group, error) {
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
		parts := strings.Split(line, ":")
		if len(parts) < 3 || parts[0] != name {
			continue
		}
		gid, _ := strconv.ParseUint(parts[2], 10, 32)
		return &Group{Name: parts[0], GID: uint32(gid)}, nil
	}
	return nil, fmt.Errorf("group %q not found", name)
}
