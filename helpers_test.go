package portscan_test

import "os"

// syscallError оборачивает errno так же, как это делает пакет net.
func syscallError(err error) error { return os.NewSyscallError("connect", err) }
