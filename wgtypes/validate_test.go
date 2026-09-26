package wgtypes_test

import (
	"strings"
	"testing"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
)

func TestConfigValidate(t *testing.T) {
	intPtr := func(i int) *int { return &i }
	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name    string
		cfg     wgtypes.Config
		wantErr string // substring; empty = valid
	}{
		{name: "empty config is valid", cfg: wgtypes.Config{}},

		// Jc / Jmin / Jmax: 16-bit, Jmax < 65535, Jmin <= Jmax
		{name: "Jc above old limit 10", cfg: wgtypes.Config{Jc: intPtr(128)}},
		{name: "Jc 0", cfg: wgtypes.Config{Jc: intPtr(0)}},
		{name: "Jc max u16", cfg: wgtypes.Config{Jc: intPtr(65535)}},
		{name: "Jc above u16", cfg: wgtypes.Config{Jc: intPtr(65536)}, wantErr: "Jc must be 0-65535"},
		{name: "Jc negative", cfg: wgtypes.Config{Jc: intPtr(-1)}, wantErr: "Jc must be"},
		{name: "Jmin below old limit 64", cfg: wgtypes.Config{Jmin: intPtr(1), Jmax: intPtr(40)}},
		{name: "Jmax 1280", cfg: wgtypes.Config{Jmin: intPtr(64), Jmax: intPtr(1280)}},
		{name: "Jmin == Jmax", cfg: wgtypes.Config{Jmin: intPtr(100), Jmax: intPtr(100)}},
		{name: "Jmin > Jmax", cfg: wgtypes.Config{Jmin: intPtr(200), Jmax: intPtr(100)}, wantErr: "Jmin (200) must be <= Jmax (100)"},
		{name: "Jmin with Jmax 0 (junk off)", cfg: wgtypes.Config{Jmin: intPtr(200), Jmax: intPtr(0)}},
		{name: "Jmax 65534", cfg: wgtypes.Config{Jmin: intPtr(10), Jmax: intPtr(65534)}},
		{name: "Jmax 65535", cfg: wgtypes.Config{Jmax: intPtr(65535)}, wantErr: "Jmax must be below 65535"},
		{name: "Jmin = Jmax = 65534 with junk", cfg: wgtypes.Config{Jc: intPtr(3), Jmin: intPtr(65534), Jmax: intPtr(65534)}, wantErr: "Jmax+1"},
		{name: "Jmin = Jmax = 65534 without junk", cfg: wgtypes.Config{Jc: intPtr(0), Jmin: intPtr(65534), Jmax: intPtr(65534)}},

		// S1-S4: padding + message size <= 65535
		{name: "S1 above old limit 64", cfg: wgtypes.Config{S1: intPtr(1132)}},
		{name: "S1 max", cfg: wgtypes.Config{S1: intPtr(65535 - 148)}},
		{name: "S1 too large", cfg: wgtypes.Config{S1: intPtr(65535 - 147)}, wantErr: "S1 must be 0-65387"},
		{name: "S2 too large", cfg: wgtypes.Config{S2: intPtr(65535 - 91)}, wantErr: "S2 must be 0-65443"},
		{name: "S3 too large", cfg: wgtypes.Config{S3: intPtr(65535 - 63)}, wantErr: "S3 must be 0-65471"},
		{name: "S4 above old limit 32", cfg: wgtypes.Config{S4: intPtr(64)}},
		{name: "S4 too large", cfg: wgtypes.Config{S4: intPtr(65535 - 31)}, wantErr: "S4 must be 0-65503"},
		{name: "S negative", cfg: wgtypes.Config{S2: intPtr(-1)}, wantErr: "S2 must be"},

		// H1-H4
		{name: "H single and ranges", cfg: wgtypes.Config{H1: strPtr("5"), H2: strPtr("100-200"), H3: strPtr("201-300"), H4: strPtr("4294967295")}},
		{name: "H standard WireGuard values", cfg: wgtypes.Config{H1: strPtr("1"), H2: strPtr("2"), H3: strPtr("3"), H4: strPtr("4")}},
		{name: "H start above end", cfg: wgtypes.Config{H1: strPtr("200-100")}, wantErr: "start is above end"},
		{name: "H not a number", cfg: wgtypes.Config{H2: strPtr("abc")}, wantErr: "H2: invalid magic header"},
		{name: "H empty", cfg: wgtypes.Config{H3: strPtr("")}, wantErr: "H3: invalid magic header"},
		{name: "H open range", cfg: wgtypes.Config{H4: strPtr("5-")}, wantErr: "H4: invalid magic header"},
		{name: "H above u32", cfg: wgtypes.Config{H1: strPtr("4294967296")}, wantErr: "H1: invalid magic header"},
		{name: "H negative", cfg: wgtypes.Config{H1: strPtr("-5")}, wantErr: "H1: invalid magic header"},
		{name: "H overlap", cfg: wgtypes.Config{H1: strPtr("100-200"), H3: strPtr("150-250")}, wantErr: "H3 (150-250) overlaps H1"},
		{name: "H touching ranges overlap", cfg: wgtypes.Config{H1: strPtr("100-200"), H2: strPtr("200")}, wantErr: "overlaps H1"},

		// I1-I5
		{name: "I all tags", cfg: wgtypes.Config{I1: strPtr("<b 0xc0ffee><c><t><r 16><rc 8><rd 4>")}},
		{name: "I text outside tags ignored", cfg: wgtypes.Config{I2: strPtr("junk <r 5> junk")}},
		{name: "I empty", cfg: wgtypes.Config{I1: strPtr("")}},
		{name: "I b empty", cfg: wgtypes.Config{I1: strPtr("<b 0x>")}, wantErr: "I1: <b 0x>: <b> needs hex bytes"},
		{name: "I b odd hex", cfg: wgtypes.Config{I1: strPtr("<b 0xabc>")}, wantErr: "needs hex bytes"},
		{name: "I b not hex", cfg: wgtypes.Config{I1: strPtr("<b 0xzz>")}, wantErr: "needs hex bytes"},
		{name: "I b without 0x", cfg: wgtypes.Config{I1: strPtr("<b c0ff>")}, wantErr: "needs hex bytes"},
		{name: "I c with value", cfg: wgtypes.Config{I3: strPtr("<c 4>")}, wantErr: "I3: <c 4>: <c> takes no value"},
		{name: "I r zero", cfg: wgtypes.Config{I1: strPtr("<r 0>")}, wantErr: "needs a positive length"},
		{name: "I r negative", cfg: wgtypes.Config{I1: strPtr("<r -1>")}, wantErr: "needs a positive length"},
		{name: "I r missing", cfg: wgtypes.Config{I1: strPtr("<r>")}, wantErr: "needs a positive length"},
		{name: "I unknown tag", cfg: wgtypes.Config{I5: strPtr("<x 1>")}, wantErr: `I5: <x 1>: unknown tag "x"`},
		{name: "I empty tag", cfg: wgtypes.Config{I1: strPtr("<>")}, wantErr: "unknown tag"},
		{name: "I unterminated tag", cfg: wgtypes.Config{I1: strPtr("<r 5")}},
		{name: "I max size", cfg: wgtypes.Config{I1: strPtr("<r 65531><c>")}},
		{name: "I too large", cfg: wgtypes.Config{I1: strPtr("<r 65532><c>")}, wantErr: "exceed 65535"},
		{name: "I int overflow sum", cfg: wgtypes.Config{I1: strPtr("<r 2147483647><r 2147483647><b 0x0102>")}, wantErr: "exceed 65535"},

		{
			name: "full valid config",
			cfg: wgtypes.Config{
				Jc: intPtr(4), Jmin: intPtr(80), Jmax: intPtr(160),
				S1: intPtr(30), S2: intPtr(40), S3: intPtr(50), S4: intPtr(8),
				H1: strPtr("1000-2000"), H2: strPtr("3000-4000"), H3: strPtr("5000-6000"), H4: strPtr("7000-8000"),
				I1: strPtr("<b 0xdeadbeef><r 32><c>"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestInitPacketSize(t *testing.T) {
	got, err := wgtypes.InitPacketSize("x<b 0xdeadbeef> <c><t><r 10><rc 3><rd 2>y")
	if err != nil {
		t.Fatal(err)
	}
	if want := 4 + 4 + 4 + 10 + 3 + 2; got != want {
		t.Fatalf("InitPacketSize = %d, want %d", got, want)
	}
}

func TestParseMagicHeader(t *testing.T) {
	for in, want := range map[string][2]uint32{
		"7":            {7, 7},
		"10-20":        {10, 20},
		"+5":           {5, 5},
		"0-0":          {0, 0},
		"1-4294967295": {1, 4294967295},
	} {
		start, end, err := wgtypes.ParseMagicHeader(in)
		if err != nil || start != want[0] || end != want[1] {
			t.Errorf("ParseMagicHeader(%q) = %d, %d, %v; want %d, %d", in, start, end, err, want[0], want[1])
		}
	}
}
