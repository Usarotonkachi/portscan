package portscan

import (
	"net/netip"
	"strconv"
	"time"
)

// State — итог проверки одного порта.
type State uint8

const (
	// StateOpen — TCP-соединение установлено.
	StateOpen State = iota + 1
	// StateClosed — соединение явно отклонено (RST, ECONNREFUSED).
	StateClosed
	// StateTimeout — подключение не завершилось за отведённое время
	// (таймаут подключения или ETIMEDOUT от ядра).
	StateTimeout
	// StateUnreachable — узел или сеть недоступны
	// (ENETUNREACH, EHOSTUNREACH, ENETDOWN, EHOSTDOWN).
	StateUnreachable
	// StateCanceled — проверка прервана отменой контекста сканирования.
	StateCanceled
	// StateError — любая другая ошибка, в том числе ошибка разрешения DNS.
	StateError
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "State(" + strconv.Itoa(int(s)) + ")"
	}
}

// Result — результат проверки одного порта на одном IP-адресе.
type Result struct {
	// Host — цель в том виде, в котором она передана в Scan
	// (IP или DNS-имя).
	Host string
	// IP — проверенный адрес. Невалиден (IsValid() == false), если
	// имя не удалось разрешить.
	IP netip.Addr
	// Port — проверенный порт.
	Port uint16
	// State — итог проверки.
	State State
	// Duration — время попытки подключения (0, если подключения не было).
	Duration time.Duration
	// Err — исходная ошибка; nil только для StateOpen. Для неразрешённых
	// имён — *ResolveError.
	Err error
}
