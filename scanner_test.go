package portscan_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Usarotonkachi/portscan"
)

// --- вспомогательные типы ---

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func refused(network, addr string) error {
	return &net.OpError{Op: "dial", Net: network, Err: errConnRefused}
}

// blockingDialer ждёт отмены контекста подключения и считает
// одновременные вызовы.
type blockingDialer struct {
	inflight, maxInflight, calls atomic.Int64
	started                      chan struct{} // получает сигнал на каждый вызов (если не nil)
}

func (d *blockingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls.Add(1)
	n := d.inflight.Add(1)
	defer d.inflight.Add(-1)
	for {
		m := d.maxInflight.Load()
		if n <= m || d.maxInflight.CompareAndSwap(m, n) {
			break
		}
	}
	if d.started != nil {
		select {
		case d.started <- struct{}{}:
		default:
		}
	}
	<-ctx.Done()
	return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
}

func mustNew(t *testing.T, opts ...portscan.Option) *portscan.Scanner {
	t.Helper()
	s, err := portscan.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustScan(t *testing.T, s *portscan.Scanner, ctx context.Context, targets []string, ports portscan.Ports) []portscan.Result {
	t.Helper()
	seq, err := s.Scan(ctx, targets, ports)
	if err != nil {
		t.Fatal(err)
	}
	return slices.Collect(seq)
}

// listen открывает слушающий порт и возвращает его номер.
func listen(t *testing.T, network, addr string) int {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// closedPort возвращает порт, на котором гарантированно никто не слушает
// (в пределах гонки с другими процессами).
func closedPort(t *testing.T, addr string) int {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func waitGoroutines(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutine leak: %d > %d\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// --- тесты ---

func TestNewValidation(t *testing.T) {
	_, err := portscan.New(
		portscan.WithConcurrency(0),
		portscan.WithConnectTimeout(-time.Second),
		portscan.WithDialer(nil),
		portscan.WithResolver(nil),
	)
	if !errors.Is(err, portscan.ErrInvalidOption) {
		t.Fatalf("got %v", err)
	}
	if s, err := portscan.New(); err != nil || s == nil {
		t.Fatalf("defaults: %v", err)
	}
}

func TestScanValidation(t *testing.T) {
	s := mustNew(t)
	ctx := t.Context()
	cases := []struct {
		name    string
		targets []string
		ports   portscan.Ports
		want    []error
	}{
		{"no targets", nil, portscan.List(80), []error{portscan.ErrNoTargets}},
		{"empty host", []string{""}, portscan.List(80), []error{portscan.ErrEmptyTarget}},
		{"bad address", []string{"300.1.1.1"}, portscan.List(80), []error{portscan.ErrInvalidTarget}},
		{"no ports", []string{"127.0.0.1"}, portscan.Ports{}, []error{portscan.ErrNoPorts}},
		{"port 0", []string{"127.0.0.1"}, portscan.List(0), []error{portscan.ErrInvalidPort}},
		{"reversed", []string{"127.0.0.1"}, portscan.Range(1000, 1), []error{portscan.ErrInvalidRange}},
		{"both", []string{""}, portscan.List(70000), []error{portscan.ErrEmptyTarget, portscan.ErrInvalidPort}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seq, err := s.Scan(ctx, c.targets, c.ports)
			if seq != nil {
				t.Fatal("iterator must be nil on error")
			}
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Fatalf("err = %v, want %v", err, w)
				}
			}
		})
	}

	var zero portscan.Scanner
	if _, err := zero.Scan(ctx, []string{"127.0.0.1"}, portscan.List(80)); err == nil {
		t.Fatal("zero Scanner must return an error, not panic")
	}
}

func TestScanLocalOpenClosed(t *testing.T) {
	open := listen(t, "tcp4", "127.0.0.1:0")
	closed := closedPort(t, "127.0.0.1:0")

	s := mustNew(t, portscan.WithConnectTimeout(2*time.Second))
	res := mustScan(t, s, t.Context(), []string{"127.0.0.1"}, portscan.List(open, closed))
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2", len(res))
	}
	for _, r := range res {
		want := portscan.StateClosed
		if int(r.Port) == open {
			want = portscan.StateOpen
		}
		if r.State != want {
			t.Errorf("port %d: state %v (err %v), want %v", r.Port, r.State, r.Err, want)
		}
		if r.Host != "127.0.0.1" || r.IP != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("unexpected host/ip: %q %v", r.Host, r.IP)
		}
		if (r.State == portscan.StateOpen) != (r.Err == nil) {
			t.Errorf("Err must be nil only for open, got %v", r.Err)
		}
	}
}

func TestScanIPv6Loopback(t *testing.T) {
	open := listen(t, "tcp6", "[::1]:0")
	s := mustNew(t)
	res := mustScan(t, s, t.Context(), []string{"::1"}, portscan.List(open))
	if len(res) != 1 || res[0].State != portscan.StateOpen {
		t.Fatalf("got %+v", res)
	}
}

func TestScanClassification(t *testing.T) {
	// Ошибка формируется так же, как её возвращает net.Dialer:
	// *net.OpError → *os.SyscallError → syscall.Errno.
	cases := map[uint16]struct {
		err  error
		want portscan.State
	}{
		1: {errConnRefused, portscan.StateClosed},
		2: {errNetUnreach, portscan.StateUnreachable},
		3: {errHostUnreach, portscan.StateUnreachable},
		4: {errTimedOut, portscan.StateTimeout},
		5: {errors.New("boom"), portscan.StateError},
	}
	dialer := dialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, p, _ := net.SplitHostPort(addr)
		n, _ := strconv.Atoi(p)
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscallError(cases[uint16(n)].err)}
	})
	s := mustNew(t, portscan.WithDialer(dialer))
	for _, r := range mustScan(t, s, t.Context(), []string{"192.0.2.1"}, portscan.Range(1, 5)) {
		if want := cases[r.Port].want; r.State != want {
			t.Errorf("port %d: got %v, want %v (err %v)", r.Port, r.State, want, r.Err)
		}
		if r.Err == nil {
			t.Errorf("port %d: Err must be set", r.Port)
		}
	}
}

func TestScanConnectTimeout(t *testing.T) {
	d := &blockingDialer{}
	s := mustNew(t, portscan.WithDialer(d), portscan.WithConnectTimeout(20*time.Millisecond))
	res := mustScan(t, s, t.Context(), []string{"192.0.2.1"}, portscan.List(80, 81))
	for _, r := range res {
		if r.State != portscan.StateTimeout {
			t.Fatalf("got %v (%v), want timeout", r.State, r.Err)
		}
		if r.Duration < 20*time.Millisecond {
			t.Fatalf("duration %v is shorter than timeout", r.Duration)
		}
	}
}

func TestScanCancel(t *testing.T) {
	base := runtime.NumGoroutine()
	d := &blockingDialer{started: make(chan struct{}, 1)}
	const conc = 8
	s := mustNew(t, portscan.WithDialer(d), portscan.WithConcurrency(conc), portscan.WithConnectTimeout(time.Hour))

	ctx, cancel := context.WithCancel(t.Context())
	seq, err := s.Scan(ctx, []string{"192.0.2.1", "192.0.2.2"}, portscan.Range(1, 10000))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-d.started
		cancel()
	}()

	var n int
	for r := range seq {
		n++
		if r.State != portscan.StateCanceled {
			t.Fatalf("got %v (%v), want canceled", r.State, r.Err)
		}
	}
	if d.inflight.Load() != 0 {
		t.Fatal("dials still running after the loop ended")
	}
	if calls := d.calls.Load(); calls > conc || int64(n) != calls {
		t.Fatalf("calls=%d results=%d: no new dials after cancel, every started dial reported", calls, n)
	}
	waitGoroutines(t, base)
}

func TestScanPreCanceled(t *testing.T) {
	d := &blockingDialer{}
	s := mustNew(t, portscan.WithDialer(d))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if res := mustScan(t, s, ctx, []string{"192.0.2.1", "example.test"}, portscan.Range(1, 100)); len(res) != 0 {
		t.Fatalf("got %d results", len(res))
	}
	if d.calls.Load() != 0 {
		t.Fatal("dialer must not be called")
	}
}

func TestScanEarlyBreak(t *testing.T) {
	base := runtime.NumGoroutine()
	var inflight atomic.Int64
	dialer := dialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		inflight.Add(1)
		defer inflight.Add(-1)
		if addr == "192.0.2.1:1" {
			return nil, refused(network, addr)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	s := mustNew(t, portscan.WithDialer(dialer), portscan.WithConcurrency(50), portscan.WithConnectTimeout(time.Hour))
	seq, err := s.Scan(t.Context(), []string{"192.0.2.1"}, portscan.Range(1, 5000))
	if err != nil {
		t.Fatal(err)
	}
	for r := range seq {
		if r.Port != 1 {
			t.Fatalf("unexpected first result %+v", r)
		}
		break
	}
	if inflight.Load() != 0 {
		t.Fatal("dials still running after break")
	}
	waitGoroutines(t, base)
}

func TestScanConcurrencyLimitAndSlowReader(t *testing.T) {
	const conc = 4
	var inflight, maxInflight, started atomic.Int64
	dialer := dialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		started.Add(1)
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for m := maxInflight.Load(); n > m && !maxInflight.CompareAndSwap(m, n); m = maxInflight.Load() {
		}
		time.Sleep(time.Millisecond)
		return nil, refused(network, addr)
	})
	s := mustNew(t, portscan.WithDialer(dialer), portscan.WithConcurrency(conc))
	seq, err := s.Scan(t.Context(), []string{"192.0.2.1", "192.0.2.2"}, portscan.Range(1, 100))
	if err != nil {
		t.Fatal(err)
	}
	var consumed int64
	seen := map[string]bool{}
	for r := range seq {
		consumed++
		seen[r.IP.String()+":"+strconv.Itoa(int(r.Port))] = true
		// Медленный читатель: сканер не должен убегать вперёд больше,
		// чем на concurrency (в работе) + concurrency (буфер) проверок.
		if ahead := started.Load() - consumed; ahead > 2*conc {
			t.Fatalf("scanner ran %d probes ahead of a slow reader", ahead)
		}
		time.Sleep(200 * time.Microsecond)
	}
	if consumed != 200 || len(seen) != 200 {
		t.Fatalf("got %d results, %d unique; want 200", consumed, len(seen))
	}
	if m := maxInflight.Load(); m > conc {
		t.Fatalf("max in-flight %d > %d", m, conc)
	}
}

func TestScanClosesConnections(t *testing.T) {
	var opened, closed atomic.Int64
	dialer := dialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		opened.Add(1)
		return &trackConn{Conn: a, closed: &closed}, nil
	})
	s := mustNew(t, portscan.WithDialer(dialer))
	res := mustScan(t, s, t.Context(), []string{"192.0.2.1"}, portscan.Range(1, 300))
	for _, r := range res {
		if r.State != portscan.StateOpen {
			t.Fatalf("got %v", r.State)
		}
	}
	if opened.Load() != 300 || closed.Load() != 300 {
		t.Fatalf("opened=%d closed=%d", opened.Load(), closed.Load())
	}
}

type trackConn struct {
	net.Conn
	once   sync.Once
	closed *atomic.Int64
}

func (c *trackConn) Close() error {
	c.once.Do(func() { c.closed.Add(1) })
	return c.Conn.Close()
}

func TestScanResolve(t *testing.T) {
	resolver := resolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		switch host {
		case "multi.test":
			return []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("::ffff:192.0.2.1"), // тот же IPv4
			}, nil
		case "empty.test":
			return nil, nil
		default:
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
	})
	var mu sync.Mutex
	dialed := map[string]int{}
	dialer := dialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed[addr]++
		mu.Unlock()
		return nil, refused(network, addr)
	})
	s := mustNew(t, portscan.WithDialer(dialer), portscan.WithResolver(resolver))
	res := mustScan(t, s, t.Context(), []string{"MULTI.test", "multi.test.", "nx.test", "empty.test"}, portscan.List(22, 80))

	byHost := map[string][]portscan.Result{}
	for _, r := range res {
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	if len(byHost["MULTI.test"]) != 4 || len(byHost["multi.test."]) != 0 {
		t.Fatalf("multi: want 2 IPs x 2 ports under the first spelling, got %v", byHost)
	}
	for _, addr := range []string{"192.0.2.1:22", "192.0.2.1:80", "[2001:db8::1]:22", "[2001:db8::1]:80"} {
		if dialed[addr] != 1 {
			t.Fatalf("%s dialed %d times, want 1 (all: %v)", addr, dialed[addr], dialed)
		}
	}

	for _, r := range byHost["nx.test"] {
		var re *portscan.ResolveError
		var de *net.DNSError
		if r.State != portscan.StateError || r.IP.IsValid() || !errors.As(r.Err, &re) || !errors.As(r.Err, &de) || !de.IsNotFound {
			t.Fatalf("nx: %+v", r)
		}
	}
	if len(byHost["nx.test"]) != 2 {
		t.Fatalf("nx: want a result per port, got %d", len(byHost["nx.test"]))
	}
	for _, r := range byHost["empty.test"] {
		if r.State != portscan.StateError || !errors.Is(r.Err, portscan.ErrNoAddresses) {
			t.Fatalf("empty: %+v", r)
		}
	}
}

func TestScannerReuseConcurrent(t *testing.T) {
	open := listen(t, "tcp4", "127.0.0.1:0")
	s := mustNew(t, portscan.WithConcurrency(16))
	ports := portscan.Union(portscan.List(open), portscan.Range(1, 20))

	seq, err := s.Scan(t.Context(), []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			// Один и тот же итератор и один сканер из разных горутин.
			var openSeen int
			for r := range seq {
				if r.State == portscan.StateOpen && int(r.Port) == open {
					openSeen++
				}
			}
			if openSeen != 1 {
				t.Errorf("open port seen %d times", openSeen)
			}
		})
	}
	wg.Wait()
}
