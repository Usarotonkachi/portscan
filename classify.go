package portscan

import (
	"context"
	"errors"
	"net"
	"os"
)

// classify определяет состояние порта по ошибке подключения. Используются
// только типизированные проверки (errors.Is / errors.As), без анализа
// текста ошибки. ctx — контекст сканирования (без таймаута подключения).
func classify(ctx context.Context, err error) State {
	// Явный ответ сети важнее одновременной отмены.
	if st, ok := classifyErrno(err); ok {
		return st
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return StateCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return StateTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return StateTimeout
	}
	return StateError
}
