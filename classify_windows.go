//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

// Коды Winsock и Win32, которые возвращает ConnectEx. Объявлены здесь,
// чтобы не тянуть golang.org/x/sys/windows ради нескольких констант.
const (
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
	wsaETIMEDOUT    syscall.Errno = 10060
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065

	errorConnectionRefused  syscall.Errno = 1225
	errorNetworkUnreachable syscall.Errno = 1231
	errorHostUnreachable    syscall.Errno = 1232
	errorSemTimeout         syscall.Errno = 121
)

func classifyErrno(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	switch errno {
	case wsaECONNREFUSED, errorConnectionRefused:
		return StateClosed, true
	case wsaENETUNREACH, wsaEHOSTUNREACH, wsaENETDOWN, wsaEHOSTDOWN,
		errorNetworkUnreachable, errorHostUnreachable:
		return StateUnreachable, true
	case wsaETIMEDOUT, errorSemTimeout:
		return StateTimeout, true
	}
	return 0, false
}
