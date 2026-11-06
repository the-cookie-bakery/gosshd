//go:build !linux

package session

import (
	"errors"

	"github.com/cookiengineer/gosshd/internal/privsep"
)

func CheckSandbox() error {
	return errors.New("session sandbox is only supported on Linux")
}

func applySessionSandbox(spec *privsep.SessionSpec) error {
	return CheckSandbox()
}
