package portscan

import (
	"errors"
	"fmt"
)

// Ports — неизменяемое описание набора TCP-портов: объединение отдельных
// портов и диапазонов. Нулевое значение — пустой набор.
//
// Конструкторы [List], [Range] и [Union] не возвращают ошибок, чтобы их
// можно было использовать прямо в аргументах; значения проверяются
// в [Scanner.Scan]:
//   - порт 0 и порты больше 65535 — ошибка [ErrInvalidPort];
//   - обратный диапазон (например, 1000–1) — ошибка [ErrInvalidRange];
//   - повторы и пересечения диапазонов схлопываются, каждый порт
//     проверяется один раз;
//   - пустой итоговый набор — ошибка [ErrNoPorts].
type Ports struct {
	spans []span
}

type span struct{ from, to int }

// List возвращает набор из отдельных портов.
func List(ports ...int) Ports {
	spans := make([]span, len(ports))
	for i, p := range ports {
		spans[i] = span{p, p}
	}
	return Ports{spans: spans}
}

// Range возвращает диапазон портов from..to включительно.
func Range(from, to int) Ports {
	return Ports{spans: []span{{from, to}}}
}

// Union объединяет несколько наборов портов.
func Union(sets ...Ports) Ports {
	var n int
	for _, s := range sets {
		n += len(s.spans)
	}
	spans := make([]span, 0, n)
	for _, s := range sets {
		spans = append(spans, s.spans...)
	}
	return Ports{spans: spans}
}

func (s span) validate() error {
	for _, p := range [...]int{s.from, s.to} {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%w: %d (allowed 1..65535)", ErrInvalidPort, p)
		}
	}
	if s.from > s.to {
		return fmt.Errorf("%w: %d-%d (start is greater than end)", ErrInvalidRange, s.from, s.to)
	}
	return nil
}

// expand проверяет набор и возвращает отсортированный список уникальных портов.
func (p Ports) expand() ([]uint16, error) {
	var (
		bits  [65536 / 64]uint64
		count int
		errs  []error
	)
	for _, s := range p.spans {
		if err := s.validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		for v := s.from; v <= s.to; v++ {
			w, b := v>>6, uint64(1)<<(v&63)
			if bits[w]&b == 0 {
				bits[w] |= b
				count++
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if count == 0 {
		return nil, ErrNoPorts
	}
	out := make([]uint16, 0, count)
	for v := 1; v <= 65535; v++ {
		if bits[v>>6]&(uint64(1)<<(v&63)) != 0 {
			out = append(out, uint16(v))
		}
	}
	return out, nil
}
