package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = time.Second
)

// Dialer устанавливает TCP-соединения. Ему удовлетворяет *net.Dialer;
// собственная реализация позволяет, например, ходить через прокси или
// подменить сеть в тестах. Реализация должна уважать отмену ctx.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver разрешает DNS-имена. Ему удовлетворяет *net.Resolver.
// Реализация должна уважать отмену ctx.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Option настраивает [Scanner] в [New].
type Option func(*Scanner) error

// WithConcurrency задаёт максимальное число одновременно выполняемых
// подключений (n >= 1). По умолчанию 100.
// Учитывайте лимит открытых файловых дескрипторов процесса.
func WithConcurrency(n int) Option {
	return func(s *Scanner) error {
		if n < 1 {
			return fmt.Errorf("%w: concurrency must be >= 1, got %d", ErrInvalidOption, n)
		}
		s.concurrency = n
		return nil
	}
}

// WithConnectTimeout задаёт таймаут одной попытки подключения (d > 0).
// По умолчанию 1 секунда.
func WithConnectTimeout(d time.Duration) Option {
	return func(s *Scanner) error {
		if d <= 0 {
			return fmt.Errorf("%w: connect timeout must be > 0, got %v", ErrInvalidOption, d)
		}
		s.timeout = d
		return nil
	}
}

// WithDialer задаёт собственный [Dialer]. По умолчанию — net.Dialer
// без TCP keep-alive.
func WithDialer(d Dialer) Option {
	return func(s *Scanner) error {
		if d == nil {
			return fmt.Errorf("%w: nil dialer", ErrInvalidOption)
		}
		s.dialer = d
		return nil
	}
}

// WithResolver задаёт собственный [Resolver]. По умолчанию —
// net.DefaultResolver.
func WithResolver(r Resolver) Option {
	return func(s *Scanner) error {
		if r == nil {
			return fmt.Errorf("%w: nil resolver", ErrInvalidOption)
		}
		s.resolver = r
		return nil
	}
}
