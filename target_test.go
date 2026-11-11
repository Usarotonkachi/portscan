package portscan

import (
	"errors"
	"slices"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in      string
		key     string
		wantErr error
	}{
		{"192.168.1.10", "a:192.168.1.10", nil},
		{"::1", "a:::1", nil},
		{"[2001:db8::1]", "a:2001:db8::1", nil},
		{"2001:DB8:0:0::1", "a:2001:db8::1", nil},
		{"fe80::1%eth0", "a:fe80::1%eth0", nil},
		{"::ffff:10.0.0.1", "a:10.0.0.1", nil},
		{"Example.COM.", "n:example.com", nil},
		{"localhost", "n:localhost", nil},
		{"_srv.my-host.local", "n:_srv.my-host.local", nil},

		{"", "", ErrEmptyTarget},
		{"   ", "", ErrEmptyTarget},
		{" 10.0.0.1", "", ErrInvalidTarget},
		{"999.1.1.1", "", ErrInvalidTarget},
		{"10.0.0", "", ErrInvalidTarget},
		{"1.2.3.4:80", "", ErrInvalidTarget},
		{"example.com:80", "", ErrInvalidTarget},
		{"http://example.com", "", ErrInvalidTarget},
		{"2001:db8::zz", "", ErrInvalidTarget},
		{"[10.0.0.1]", "", ErrInvalidTarget},
		{"[example.com]", "", ErrInvalidTarget},
		{"a..b", "", ErrInvalidTarget},
		{"-bad.com", "", ErrInvalidTarget},
		{"bad-.com", "", ErrInvalidTarget},
		{"с.рф", "", ErrInvalidTarget},        // IDN нужно передавать в punycode
		{"10.0.0.0/24", "", ErrInvalidTarget}, // CIDR не поддерживается
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseTarget(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.key() != tt.key || got.input != tt.in {
				t.Fatalf("got key=%q input=%q, want key=%q", got.key(), got.input, tt.key)
			}
		})
	}
}

func TestParseTargetsDedupAndErrors(t *testing.T) {
	ts, err := parseTargets([]string{"10.0.0.1", "10.0.0.1", "::ffff:10.0.0.1", "Host.example", "host.example."})
	if err != nil {
		t.Fatal(err)
	}
	var inputs []string
	for _, tg := range ts {
		inputs = append(inputs, tg.input)
	}
	if want := []string{"10.0.0.1", "Host.example"}; !slices.Equal(inputs, want) {
		t.Fatalf("got %v, want %v (first occurrence kept)", inputs, want)
	}

	if _, err := parseTargets(nil); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("nil targets: %v", err)
	}

	_, err = parseTargets([]string{"ok.example", "", "bad host"})
	if !errors.Is(err, ErrEmptyTarget) || !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("want all target errors joined, got %v", err)
	}
	var te *TargetError
	if !errors.As(err, &te) || te.Target != "" {
		t.Fatalf("want *TargetError for the empty target, got %#v", te)
	}
}
