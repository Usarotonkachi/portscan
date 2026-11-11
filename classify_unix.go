//go:build unix

package portscan

import (
	"errors"
	"syscall"
)

func classifyErrno(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	switch errno {
	case syscall.ECONNREFUSED:
		return StateClosed, true
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN, syscall.EHOSTDOWN:
		return StateUnreachable, true
	case syscall.ETIMEDOUT:
		return StateTimeout, true
	}
	return 0, false
}
