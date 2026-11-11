package portscan

import (
	"context"
	"errors"
	"iter"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// maxParallelLookups ограничивает число одновременных DNS-запросов
// одного сканирования (дополнительно к лимиту concurrency).
const maxParallelLookups = 16

// maxResultBuffer ограничивает буфер готовых результатов.
const maxResultBuffer = 1024

// Scanner выполняет TCP Connect-сканирование. Создаётся через [New],
// после создания не изменяется, поэтому безопасен для одновременного
// использования из нескольких горутин и повторного использования.
type Scanner struct {
	concurrency int
	timeout     time.Duration
	dialer      Dialer
	resolver    Resolver
}

// New создаёт сканер. Ошибки всех некорректных опций объединяются и
// оборачивают [ErrInvalidOption].
func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency: defaultConcurrency,
		timeout:     defaultConnectTimeout,
		dialer:      &net.Dialer{KeepAlive: -1},
		resolver:    net.DefaultResolver,
	}
	var errs []error
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return s, nil
}

// Scan синхронно проверяет цели и порты и возвращает итератор
// результатов. Ошибки валидации (см. [TargetError], [ErrNoTargets],
// [ErrNoPorts], [ErrInvalidPort], [ErrInvalidRange]) объединяются через
// errors.Join.
//
// Цели: IPv4, IPv6 (в том числе в квадратных скобках и с зоной) или
// DNS-имя. Повторы удаляются. Имя
// разрешается во все адреса (IPv4 и IPv6), каждый проверяется отдельно;
// если имя не разрешилось, для каждого порта выдаётся результат
// [StateError] с [*ResolveError] и невалидным IP.
//
// Сканирование запускается при каждом проходе по итератору (повторный
// range — новое сканирование). Результаты выдаются по мере готовности,
// порядок не гарантируется. Чтение итератора создаёт обратное давление:
// пока потребитель обрабатывает результат, новых подключений сверх
// лимита concurrency не открывается.
//
// Отмена ctx или выход из цикла останавливают запуск новых проверок,
// уже запущенные прерываются. При отмене ctx результаты прерванных
// проверок ([StateCanceled]) выдаются потребителю; не начатые проверки
// не выдаются вовсе — признак неполноты результата: ctx.Err() != nil.
// Когда цикл range завершился, все соединения закрыты, а горутины
// сканирования остановлены.
func (s *Scanner) Scan(ctx context.Context, targets []string, ports Ports) (iter.Seq[Result], error) {
	if s == nil || s.dialer == nil || s.resolver == nil || s.concurrency < 1 || s.timeout <= 0 {
		return nil, errors.New("portscan: Scanner must be created with New")
	}
	if ctx == nil {
		return nil, errors.New("portscan: nil context")
	}
	ts, terr := parseTargets(targets)
	ps, perr := ports.expand()
	if err := errors.Join(terr, perr); err != nil {
		return nil, err
	}
	return func(yield func(Result) bool) {
		s.run(ctx, ts, ps, yield)
	}, nil
}

func (s *Scanner) run(parent context.Context, ts []target, ps []uint16, yield func(Result) bool) {
	ctx, cancel := context.WithCancel(parent)
	results := make(chan Result, min(s.concurrency, maxResultBuffer))
	go s.dispatch(ctx, ts, ps, results)

	// Выполняется и при break, и при панике в теле цикла пользователя:
	// останавливаем раздачу и дожидаемся закрытия канала, т.е. завершения
	// всех проверок и горутин.
	defer func() {
		cancel()
		for range results {
		}
	}()

	for r := range results {
		if !yield(r) {
			return
		}
	}
}

// resolution — цель с готовым списком адресов или ошибкой разрешения.
type resolution struct {
	t     target
	addrs []netip.Addr
	err   error
}

// dispatch раздаёт проверки, держа не более s.concurrency одновременно,
// и закрывает out после завершения всех проверок.
func (s *Scanner) dispatch(ctx context.Context, ts []target, ps []uint16, out chan<- Result) {
	var wg sync.WaitGroup
	resolved := s.resolveAll(ctx, ts)

	// Порядок defer: дочитать resolved (дождаться горутин DNS) →
	// дождаться проверок → закрыть out.
	defer close(out)
	defer wg.Wait()
	defer func() {
		for range resolved {
		}
	}()

	sem := make(chan struct{}, s.concurrency)
	for res := range resolved {
		if res.err != nil {
			for _, p := range ps {
				r := Result{Host: res.t.input, Port: p, State: StateError, Err: res.err}
				select {
				case out <- r:
				case <-ctx.Done():
					return
				}
			}
			continue
		}
		for _, ip := range res.addrs {
			for _, p := range ps {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				// select выбирает случайно, если готовы обе ветки.
				if ctx.Err() != nil {
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					r := s.probe(ctx, res.t.input, ip, p)
					// Слот освобождается только после отправки: медленный
					// потребитель ограничивает число горутин, а не копит их.
					// Отправка не блокируется навсегда: run всегда дочитывает канал.
					out <- r
					<-sem
				}()
			}
		}
	}
}

// resolveAll отдаёт цели с адресами. DNS-имена разрешаются параллельно
// (не более maxParallelLookups). Канал закрывается, когда все горутины
// завершены.
func (s *Scanner) resolveAll(ctx context.Context, ts []target) <-chan resolution {
	out := make(chan resolution)
	go func() {
		var wg sync.WaitGroup
		defer close(out)
		defer wg.Wait()

		sem := make(chan struct{}, min(s.concurrency, maxParallelLookups))
		for _, t := range ts {
			if t.addr.IsValid() {
				select {
				case out <- resolution{t: t, addrs: []netip.Addr{t.addr}}:
				case <-ctx.Done():
					return
				}
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				addrs, err := s.lookup(ctx, t.name)
				if ctx.Err() != nil {
					return // сканирование отменено: цель не начата
				}
				select {
				case out <- resolution{t: t, addrs: addrs, err: err}:
				case <-ctx.Done():
				}
			}()
		}
	}()
	return out
}

// lookup разрешает имя во все адреса (IPv4 и IPv6), удаляя повторы.
func (s *Scanner) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	raw, err := s.resolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, &ResolveError{Host: name, Err: err}
	}
	addrs := make([]netip.Addr, 0, len(raw))
	for _, a := range raw {
		a = a.Unmap()
		if a.IsValid() && !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, &ResolveError{Host: name, Err: ErrNoAddresses}
	}
	return addrs, nil
}

// probe выполняет одну попытку TCP-подключения.
func (s *Scanner) probe(ctx context.Context, host string, ip netip.Addr, port uint16) Result {
	r := Result{Host: host, IP: ip, Port: port}

	dctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	conn, err := s.dialer.DialContext(dctx, "tcp", netip.AddrPortFrom(ip, port).String())
	r.Duration = time.Since(start)

	if conn != nil {
		if tc, ok := conn.(*net.TCPConn); ok {
			// RST вместо FIN: не оставляем сокеты в TIME_WAIT
			// при сканировании тысяч портов.
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	}
	if err != nil {
		r.State, r.Err = classify(ctx, err), err
		return r
	}
	r.State = StateOpen
	return r
}
