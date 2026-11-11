//go:build !unix && !windows

package portscan

// На прочих платформах (js, wasip1, plan9) коды ошибок не разбираются:
// остаются только проверки таймаута и отмены из classify.
func classifyErrno(error) (State, bool) { return 0, false }
