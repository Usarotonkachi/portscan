package portscan_test

import (
	"context"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/Usarotonkachi/portscan"
)

func Example() {
	// Локальный сервер, чтобы пример был воспроизводимым.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ln.Close()
	open := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.List(open))
	if err != nil {
		fmt.Println(err)
		return
	}
	for r := range results {
		fmt.Println(r.Host, r.Port == uint16(open), r.State)
	}
	if ctx.Err() != nil {
		fmt.Println("scan interrupted:", ctx.Err())
	}
	// Output:
	// 127.0.0.1 true open
}

func ExampleScanner_Scan_validation() {
	scanner, _ := portscan.New()
	_, err := scanner.Scan(context.Background(), []string{"", "10.0.0.1:22"}, portscan.Range(0, 10))
	fmt.Println(err)
	// Output:
	// portscan: empty target (target "")
	// portscan: invalid target: unexpected character ':' (host:port, URL or malformed IP?) (target "10.0.0.1:22")
	// portscan: invalid port: 0 (allowed 1..65535)
}

func ExampleScanner_Scan_collect() {
	scanner, _ := portscan.New()
	seq, _ := scanner.Scan(context.Background(), []string{"127.0.0.1"}, portscan.List(1))
	all := slices.Collect(seq) // итератор совместим с пакетами slices/maps
	fmt.Println(len(all))
	// Output:
	// 1
}
