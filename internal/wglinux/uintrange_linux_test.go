//go:build linux
// +build linux

package wglinux

import (
	"testing"
)

func TestParseUintRangeString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLo  uint32
		wantHi  uint32
		wantErr bool
	}{
		{
			name:   "single value",
			input:  "12345",
			wantLo: 12345,
			wantHi: 12345,
		},
		{
			name:   "range",
			input:  "100-200",
			wantLo: 100,
			wantHi: 200,
		},
		{
			name:   "equal range",
			input:  "42-42",
			wantLo: 42,
			wantHi: 42,
		},
		{
			name:   "zero",
			input:  "0",
			wantLo: 0,
			wantHi: 0,
		},
		{
			name:   "zero range",
			input:  "0-0",
			wantLo: 0,
			wantHi: 0,
		},
		{
			name:   "large values",
			input:  "150000000-200000000",
			wantLo: 150000000,
			wantHi: 200000000,
		},
		{
			name:   "max uint32",
			input:  "4294967295",
			wantLo: 4294967295,
			wantHi: 4294967295,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "reversed range",
			input:   "200-100",
			wantErr: true,
		},
		{
			name:    "negative lo",
			input:   "-5",
			wantErr: true,
		},
		{
			name:    "overflow",
			input:   "4294967296",
			wantErr: true,
		},
		{
			name:    "non-numeric",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "non-numeric hi",
			input:   "100-abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lo, hi, err := parseUintRangeString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got lo=%d hi=%d", tt.input, lo, hi)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if lo != tt.wantLo {
				t.Errorf("lo: got %d, want %d", lo, tt.wantLo)
			}
			if hi != tt.wantHi {
				t.Errorf("hi: got %d, want %d", hi, tt.wantHi)
			}
		})
	}
}

func TestFormatUintRange(t *testing.T) {
	tests := []struct {
		name string
		lo   uint32
		hi   uint32
		want string
	}{
		{name: "single", lo: 42, hi: 42, want: "42"},
		{name: "range", lo: 100, hi: 200, want: "100-200"},
		{name: "zero", lo: 0, hi: 0, want: "0"},
		{name: "large", lo: 150000000, hi: 200000000, want: "150000000-200000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatUintRange(tt.lo, tt.hi)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPackUnpackUintRange(t *testing.T) {
	tests := []struct {
		name string
		lo   uint32
		hi   uint32
	}{
		{name: "zero", lo: 0, hi: 0},
		{name: "same", lo: 42, hi: 42},
		{name: "range", lo: 100, hi: 200},
		{name: "large", lo: 150000000, hi: 200000000},
		{name: "max", lo: 0xFFFFFFFF, hi: 0xFFFFFFFF},
		{name: "lo_zero_hi_max", lo: 0, hi: 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := packUintRange(tt.lo, tt.hi)
			gotLo, gotHi := unpackUintRange(packed)
			if gotLo != tt.lo || gotHi != tt.hi {
				t.Errorf("pack/unpack(%d, %d): got (%d, %d)", tt.lo, tt.hi, gotLo, gotHi)
			}
		})
	}
}

func TestPackUintRangeLayout(t *testing.T) {
	// Verify the exact bit layout matches amneziawg-go:
	// uint64(hi)<<32 | uint64(lo)
	lo := uint32(100)
	hi := uint32(200)
	packed := packUintRange(lo, hi)
	want := uint64(200)<<32 | uint64(100)
	if packed != want {
		t.Errorf("packed layout: got 0x%016x, want 0x%016x", packed, want)
	}
}

func TestUintRangeStringToUint64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{
			name:  "single value",
			input: "12345",
			want:  uint64(12345)<<32 | uint64(12345),
		},
		{
			name:  "range",
			input: "100-200",
			want:  uint64(200)<<32 | uint64(100),
		},
		{
			name:    "invalid",
			input:   "abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := uintRangeStringToUint64(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got 0x%016x, want 0x%016x", got, tt.want)
			}
		})
	}
}

func TestUintRangeUint64ToString(t *testing.T) {
	tests := []struct {
		name  string
		input uint64
		want  string
	}{
		{
			name:  "single value",
			input: uint64(42)<<32 | uint64(42),
			want:  "42",
		},
		{
			name:  "range",
			input: uint64(200)<<32 | uint64(100),
			want:  "100-200",
		},
		{
			name:  "zero",
			input: 0,
			want:  "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uintRangeUint64ToString(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUintRangeStringToUint32(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint32
		wantErr bool
	}{
		{
			name:  "single value",
			input: "12345",
			want:  12345,
		},
		{
			name:  "range drops hi",
			input: "100-200",
			want:  100,
		},
		{
			name:    "invalid",
			input:   "abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := uintRangeStringToUint32(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUintRangeUint32ToString(t *testing.T) {
	got := uintRangeUint32ToString(42)
	if got != "42" {
		t.Errorf("got %q, want %q", got, "42")
	}
}

func TestUintRangeRoundTrip(t *testing.T) {
	// String → uint64 → string round-trip.
	tests := []string{
		"0",
		"42",
		"100-200",
		"150000000-200000000",
		"4294967295",
		"0-4294967295",
	}

	for _, s := range tests {
		t.Run("uint64/"+s, func(t *testing.T) {
			v, err := uintRangeStringToUint64(s)
			if err != nil {
				t.Fatalf("toUint64: %v", err)
			}
			got := uintRangeUint64ToString(v)
			if got != s {
				t.Errorf("round-trip: got %q, want %q", got, s)
			}
		})
	}

	// String → uint32 → string round-trip (lossy for ranges).
	t.Run("uint32/single", func(t *testing.T) {
		v, err := uintRangeStringToUint32("42")
		if err != nil {
			t.Fatalf("toUint32: %v", err)
		}
		got := uintRangeUint32ToString(v)
		if got != "42" {
			t.Errorf("round-trip: got %q, want %q", got, "42")
		}
	})

	// Lossy: "100-200" → uint32(100) → "100"
	t.Run("uint32/range_lossy", func(t *testing.T) {
		v, err := uintRangeStringToUint32("100-200")
		if err != nil {
			t.Fatalf("toUint32: %v", err)
		}
		got := uintRangeUint32ToString(v)
		if got != "100" {
			t.Errorf("round-trip: got %q, want %q", got, "100")
		}
	})
}
