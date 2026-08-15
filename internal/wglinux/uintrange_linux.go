//go:build linux
// +build linux

package wglinux

import (
	"fmt"
	"strconv"
	"strings"
)

// parseUintRangeString parses a UintRange string representation ("val" or
// "lo-hi") into its lo and hi uint32 components. A single value "val" is
// treated as a range where lo == hi.
func parseUintRangeString(s string) (lo, hi uint32, err error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) == 0 || parts[0] == "" {
		return 0, 0, fmt.Errorf("wglinux: empty UintRange string")
	}

	loVal, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("wglinux: invalid UintRange lo value %q: %w", parts[0], err)
	}

	hiVal := loVal
	if len(parts) == 2 {
		hiVal, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("wglinux: invalid UintRange hi value %q: %w", parts[1], err)
		}
	}

	if hiVal < loVal {
		return 0, 0, fmt.Errorf("wglinux: invalid UintRange: hi (%d) < lo (%d)", hiVal, loVal)
	}

	return uint32(loVal), uint32(hiVal), nil
}

// formatUintRange formats a UintRange as a string. If lo == hi, it returns
// "val"; otherwise it returns "lo-hi".
func formatUintRange(lo, hi uint32) string {
	if lo == hi {
		return strconv.FormatUint(uint64(lo), 10)
	}
	return strconv.FormatUint(uint64(lo), 10) + "-" + strconv.FormatUint(uint64(hi), 10)
}

// packUintRange packs lo and hi uint32 values into a single uint64 using the
// AWG 3 kernel layout: hi in the upper 32 bits, lo in the lower 32 bits.
// This matches amneziawg-go's UintRange type and the AWG 3 kernel module.
func packUintRange(lo, hi uint32) uint64 {
	return uint64(hi)<<32 | uint64(lo)
}

// unpackUintRange unpacks a uint64 into lo and hi uint32 values.
func unpackUintRange(v uint64) (lo, hi uint32) {
	return uint32(v), uint32(v >> 32)
}

// uintRangeStringToUint64 converts a UintRange string ("val" or "lo-hi") to
// the packed uint64 representation used by AWG 3 kernels.
func uintRangeStringToUint64(s string) (uint64, error) {
	lo, hi, err := parseUintRangeString(s)
	if err != nil {
		return 0, err
	}
	return packUintRange(lo, hi), nil
}

// uintRangeUint64ToString converts a packed uint64 UintRange to the string
// representation ("val" or "lo-hi").
func uintRangeUint64ToString(v uint64) string {
	lo, hi := unpackUintRange(v)
	return formatUintRange(lo, hi)
}

// uintRangeStringToUint32 converts a UintRange string ("val" or "lo-hi") to
// a uint32 by extracting only the lo value. This matches AWG 1 kernel behavior
// where only a single value is stored.
func uintRangeStringToUint32(s string) (uint32, error) {
	lo, _, err := parseUintRangeString(s)
	if err != nil {
		return 0, err
	}
	return lo, nil
}

// uintRangeUint32ToString converts a uint32 value to a UintRange string.
// Since only a single value is available, the result is always "val" (lo == hi).
func uintRangeUint32ToString(v uint32) string {
	return formatUintRange(v, v)
}
