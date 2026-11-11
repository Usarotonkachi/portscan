//go:build unix

package portscan_test

import "syscall"

var (
	errConnRefused error = syscall.ECONNREFUSED
	errNetUnreach  error = syscall.ENETUNREACH
	errHostUnreach error = syscall.EHOSTUNREACH
	errTimedOut    error = syscall.ETIMEDOUT
)
