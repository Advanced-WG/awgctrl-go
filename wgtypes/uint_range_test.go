package wgtypes

import "testing"

func TestParseUintRange(t *testing.T) {
	tests := []struct {
		in      string
		want    UintRange
		wantErr bool
	}{
		{in: "10", want: UintRange{Min: 10, Max: 10}},
		{in: "10-100", want: UintRange{Min: 10, Max: 100}},
		{in: " 3-7 ", want: UintRange{Min: 3, Max: 7}},
		{in: "0", want: UintRange{}},
		{in: "100-10", wantErr: true},
		{in: "", wantErr: true},
		{in: "65536", wantErr: true},
		{in: "10-20-30", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseUintRange(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseUintRange(%q) = %+v, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseUintRange(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseUintRange(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestUintRangeString(t *testing.T) {
	tests := []struct {
		r    UintRange
		want string
	}{
		{r: UintRange{Min: 10, Max: 10}, want: "10"},
		{r: UintRange{Min: 10, Max: 100}, want: "10-100"},
		{r: UintRange{Min: 10}, want: "10"},
		{r: UintRange{}, want: "0"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestUintRangePackU16(t *testing.T) {
	r := UintRange{Min: 10, Max: 100}
	packed := r.PackU16()
	if packed != uint32(100)<<16|10 {
		t.Errorf("PackU16() = %#x, want hi=100 lo=10", packed)
	}
	got := UintRangeFromPackedU16(packed)
	if got != r {
		t.Errorf("FromPackedU16(%#x) = %+v, want %+v", packed, got, r)
	}
}

func TestUintRangeFromPackedU16Legacy(t *testing.T) {
	got := UintRangeFromPackedU16(5)
	want := UintRange{Min: 5, Max: 5}
	if got != want {
		t.Errorf("legacy 5 = %+v, want %+v", got, want)
	}
	if !UintRangeFromPackedU16(0).IsZero() {
		t.Error("packed 0 should be zero")
	}
}

func TestUintRangeFromPackedU16ZeroMax(t *testing.T) {
	got := UintRangeFromPackedU16(uint32(100)<<16 | 0)
	want := UintRange{Min: 0, Max: 100}
	if got != want {
		t.Errorf("0-100 = %+v, want %+v", got, want)
	}
}
