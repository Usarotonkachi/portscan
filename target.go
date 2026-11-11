package portscan

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// target — проверенная цель: либо IP-литерал, либо DNS-имя.
type target struct {
	input string     // как передал пользователь, уходит в Result.Host
	addr  netip.Addr // валиден для IP-литерала
	name  string     // нормализованное DNS-имя, если это не IP
}

func (t target) key() string {
	if t.addr.IsValid() {
		return "a:" + t.addr.String()
	}
	return "n:" + t.name
}

// parseTargets проверяет все цели и удаляет повторы (с учётом
// нормализации: регистр имени, завершающая точка, форма записи IP).
// Возвращает объединение ошибок по всем некорректным целям.
func parseTargets(in []string) ([]target, error) {
	if len(in) == 0 {
		return nil, ErrNoTargets
	}
	var (
		out  = make([]target, 0, len(in))
		seen = make(map[string]struct{}, len(in))
		errs []error
	)
	for _, s := range in {
		t, err := parseTarget(s)
		if err != nil {
			errs = append(errs, &TargetError{Target: s, Err: err})
			continue
		}
		k := t.key()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, t)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func parseTarget(s string) (target, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return target{}, ErrEmptyTarget
	}
	if trimmed != s {
		return target{}, fmt.Errorf("%w: leading or trailing whitespace", ErrInvalidTarget)
	}

	v := s
	bracketed := strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]")
	if bracketed {
		v = v[1 : len(v)-1]
	}
	if a, err := netip.ParseAddr(v); err == nil {
		if bracketed && !a.Is6() {
			return target{}, fmt.Errorf("%w: brackets are allowed only around IPv6", ErrInvalidTarget)
		}
		// ::ffff:10.0.0.1 проверяем как обычный IPv4.
		return target{input: s, addr: a.Unmap()}, nil
	}
	if bracketed {
		return target{}, fmt.Errorf("%w: malformed IPv6 address", ErrInvalidTarget)
	}

	name, err := normalizeHostname(v)
	if err != nil {
		return target{}, err
	}
	return target{input: s, name: name}, nil
}

// normalizeHostname проверяет синтаксис DNS-имени (RFC 1123, с допуском '_')
// и приводит его к нижнему регистру без завершающей точки.
func normalizeHostname(s string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(s, "."))
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("%w: hostname length must be 1..253", ErrInvalidTarget)
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", fmt.Errorf("%w: hostname label length must be 1..63", ErrInvalidTarget)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("%w: hostname label starts or ends with '-'", ErrInvalidTarget)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("%w: unexpected character %q (host:port, URL or malformed IP?)", ErrInvalidTarget, c)
			}
		}
	}
	// Полностью числовой TLD не бывает: "999.1.1.1" или "10.1" —
	// это испорченный IPv4, а не имя, уходить с ним в DNS не нужно.
	if isDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: malformed IPv4 address", ErrInvalidTarget)
	}
	return name, nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
