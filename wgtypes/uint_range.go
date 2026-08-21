package wgtypes

import (
	"fmt"
	"strconv"
	"strings"
)

// UintRange is an AWG 3 inclusive range (Min..Max).
//
// The zero value (Min == Max == 0) means the field is unset, matching
// kernel u16_range_is_zero. A single value uses Min == Max.
//
// On the wire:
//   - Kernel netlink: packed u16_range_t as NLA_U32 (hi<<16 | lo)
//   - Userspace UAPI: "10" or "10-100"
type UintRange struct {
	Min int
	Max int
}

// ParseUintRange parses a UAPI/wg-quick range: "10" or "10-100".
func ParseUintRange(s string) (UintRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return UintRange{}, fmt.Errorf("wgtypes: empty range")
	}
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return UintRange{}, fmt.Errorf("wgtypes: invalid range %q", s)
	}
	lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return UintRange{}, fmt.Errorf("wgtypes: invalid range %q: %w", s, err)
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err != nil {
			return UintRange{}, fmt.Errorf("wgtypes: invalid range %q: %w", s, err)
		}
		if hi < lo {
			return UintRange{}, fmt.Errorf("wgtypes: invalid range %q: max < min", s)
		}
	}
	return UintRange{Min: int(lo), Max: int(hi)}, nil
}

// IsZero reports whether r is the unset zero value.
func (r UintRange) IsZero() bool {
	return r.Min == 0 && r.Max == 0
}

// String renders the UAPI form: "10" or "10-100".
func (r UintRange) String() string {
	min, max := r.bounds()
	if min == max {
		return strconv.Itoa(min)
	}
	return fmt.Sprintf("%d-%d", min, max)
}

// PackU16 packs r as a kernel u16_range_t (hi<<16 | lo).
func (r UintRange) PackU16() uint32 {
	min, max := r.bounds()
	return uint32(uint16(max))<<16 | uint32(uint16(min))
}

// UintRangeFromPackedU16 unpacks a kernel u16_range_t.
//
// If the high 16 bits are 0, the value is treated as a single number
// (legacy dumps that stored lo only): Min == Max == lo. Packed 0 stays zero.
func UintRangeFromPackedU16(v uint32) UintRange {
	lo := int(uint16(v))
	hi := int(v >> 16)
	if hi == 0 {
		return UintRange{Min: lo, Max: lo}
	}
	return UintRange{Min: lo, Max: hi}
}

func (r UintRange) bounds() (min, max int) {
	min, max = r.Min, r.Max
	if max == 0 {
		max = min
	}
	return min, max
}
