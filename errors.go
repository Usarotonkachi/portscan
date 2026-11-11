package portscan

import (
	"errors"
	"fmt"
)

// Ошибки валидации входных данных. Возвращаются из [New] и [Scanner.Scan]
// (обёрнутые, проверять через [errors.Is]).
var (
	// ErrInvalidOption — недопустимое значение опции [New].
	ErrInvalidOption = errors.New("portscan: invalid option")

	// ErrNoTargets — не передано ни одной цели.
	ErrNoTargets = errors.New("portscan: no targets")
	// ErrEmptyTarget — цель является пустой строкой или состоит из пробелов.
	ErrEmptyTarget = errors.New("portscan: empty target")
	// ErrInvalidTarget — цель не является ни IP-адресом, ни синтаксически
	// корректным DNS-именем.
	ErrInvalidTarget = errors.New("portscan: invalid target")

	// ErrNoPorts — итоговый набор портов пуст.
	ErrNoPorts = errors.New("portscan: no ports")
	// ErrInvalidPort — порт вне диапазона 1..65535.
	ErrInvalidPort = errors.New("portscan: invalid port")
	// ErrInvalidRange — у диапазона портов начало больше конца.
	ErrInvalidRange = errors.New("portscan: invalid port range")
)

// ErrNoAddresses означает, что DNS-имя разрешилось без ошибки,
// но не вернуло ни одного адреса. Приходит внутри [ResolveError].
var ErrNoAddresses = errors.New("portscan: host has no addresses")

// TargetError описывает некорректную цель, переданную в [Scanner.Scan].
type TargetError struct {
	Target string // цель в том виде, в котором её передали
	Err    error  // ErrEmptyTarget или ErrInvalidTarget (возможно, обёрнутая)
}

func (e *TargetError) Error() string { return fmt.Sprintf("%v (target %q)", e.Err, e.Target) }
func (e *TargetError) Unwrap() error { return e.Err }

// ResolveError — ошибка разрешения DNS-имени. Передаётся в [Result.Err]
// для каждого порта цели, которую не удалось разрешить; исходная ошибка
// резолвера (обычно *net.DNSError) доступна через [errors.As].
type ResolveError struct {
	Host string // DNS-имя (нормализованное)
	Err  error
}

func (e *ResolveError) Error() string { return fmt.Sprintf("portscan: resolve %q: %v", e.Host, e.Err) }
func (e *ResolveError) Unwrap() error { return e.Err }
