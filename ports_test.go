package portscan

import (
	"errors"
	"slices"
	"testing"
)

func TestPortsExpand(t *testing.T) {
	tests := []struct {
		name    string
		ports   Ports
		want    []uint16
		wantErr error
	}{
		{"list", List(80, 22, 443), []uint16{22, 80, 443}, nil},
		{"range", Range(1, 3), []uint16{1, 2, 3}, nil},
		{"single range", Range(7, 7), []uint16{7}, nil},
		{"union with overlap and duplicates", Union(Range(10, 12), List(11, 12, 12, 1), Range(12, 13)), []uint16{1, 10, 11, 12, 13}, nil},
		{"bounds", List(1, 65535), []uint16{1, 65535}, nil},
		{"zero value", Ports{}, nil, ErrNoPorts},
		{"empty list", List(), nil, ErrNoPorts},
		{"empty union", Union(), nil, ErrNoPorts},
		{"port 0", List(0), nil, ErrInvalidPort},
		{"port 65536", List(65536), nil, ErrInvalidPort},
		{"negative", List(-1), nil, ErrInvalidPort},
		{"range above max", Range(65000, 70000), nil, ErrInvalidPort},
		{"reversed range", Range(1000, 1), nil, ErrInvalidRange},
		{"one bad element spoils the set", Union(List(80), List(0)), nil, ErrInvalidPort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ports.expand()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortsFullRange(t *testing.T) {
	got, err := Range(1, 65535).expand()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 65535 || got[0] != 1 || got[len(got)-1] != 65535 {
		t.Fatalf("unexpected full range: len=%d", len(got))
	}
}

func TestPortsAllErrorsReported(t *testing.T) {
	_, err := Union(List(0), Range(5, 1)).expand()
	if !errors.Is(err, ErrInvalidPort) || !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("want both errors joined, got %v", err)
	}
}
