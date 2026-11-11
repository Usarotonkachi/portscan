//go:build windows

package portscan_test

import "syscall"

var (
	errConnRefused error = syscall.Errno(10061) // WSAECONNREFUSED
	errNetUnreach  error = syscall.Errno(10051) // WSAENETUNREACH
	errHostUnreach error = syscall.Errno(10065) // WSAEHOSTUNREACH
	errTimedOut    error = syscall.Errno(10060) // WSAETIMEDOUT
)
