package wgtypes

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Kernel limits, mirrored from the AmneziaWG kernel module (device.c,
// netlink.c, junk.c, magic_header.c). Validate rejects exactly what the kernel
// rejects, so an error is reported before any netlink round trip instead of
// an opaque EINVAL. Recommended (much smaller) values are a policy matter
// for callers; see docs/AWG_PARAMETERS.md.
const (
	// maxMessageSize is the kernel's MESSAGE_MAX_SIZE (largest UDP payload).
	maxMessageSize = 65535

	messageInitiationSize = 148
	messageResponseSize   = 92
	messageCookieSize     = 64
	messageTransportSize  = 32 // header plus authentication tag of an empty packet
)

// Validate checks cfg against the limits of the kernel's netlink encoding and
// the AmneziaWG kernel module, and returns an error describing the first
// violation found.
//
// ListenPort and every peer's PersistentKeepaliveInterval (whole seconds) are
// 16-bit and FirewallMark is 32-bit; none of them may be negative. Larger
// values would otherwise wrap, e.g. ListenPort 70000 becomes 4464.
//
// Jc, Jmin and Jmax are 16-bit and Jmax must stay below 65535; Jmin <= Jmax
// is checked when both are set (Jmax 0 disables junk packets). S1-S4 plus the
// size of their message must fit in 65535 bytes. H1-H4 are "N" or "N-M"
// (32-bit, N <= M) and the ones set must not overlap. I1-I5 must use the
// tags the kernel knows (<b 0xHEX>, <c>, <t>, <r N>, <rc N>, <rd N>) and
// describe at most 65535 bytes.
//
// Only fields that are set are checked, so a partial update is validated on
// its own; relations to values already on the device cannot be checked here
// (Client.ConfigureDevice does that for partial Jc/Jmin/Jmax and H1-H4 updates).
// The amneziawg-go userspace daemon is stricter in one point: it rejects Jc,
// Jmin and Jmax of 0.
func (cfg *Config) Validate() error {
	if cfg.ListenPort != nil && (*cfg.ListenPort < 0 || *cfg.ListenPort > 0xffff) {
		return fmt.Errorf("wgtypes: ListenPort must be 0-65535, got %d", *cfg.ListenPort)
	}
	if cfg.FirewallMark != nil && (*cfg.FirewallMark < 0 || int64(*cfg.FirewallMark) > 0xffffffff) {
		return fmt.Errorf("wgtypes: FirewallMark must be 0-4294967295, got %d", *cfg.FirewallMark)
	}
	for _, p := range cfg.Peers {
		if ka := p.PersistentKeepaliveInterval; ka != nil && (*ka < 0 || *ka > 0xffff*time.Second) {
			return fmt.Errorf("wgtypes: peer %s: PersistentKeepaliveInterval must be 0-65535s, got %s", p.PublicKey, *ka)
		}
	}

	u16 := []struct {
		name string
		v    *int
	}{{"Jc", cfg.Jc}, {"Jmin", cfg.Jmin}, {"Jmax", cfg.Jmax}}
	for _, f := range u16 {
		if f.v != nil && (*f.v < 0 || *f.v > 0xffff) {
			return fmt.Errorf("wgtypes: %s must be 0-65535, got %d", f.name, *f.v)
		}
	}
	if cfg.Jmax != nil && *cfg.Jmax >= maxMessageSize {
		return fmt.Errorf("wgtypes: Jmax must be below %d, got %d", maxMessageSize, *cfg.Jmax)
	}
	// With junk packets on, the kernel bumps Jmax by one when Jmin == Jmax,
	// which must still stay below 65535.
	if cfg.Jmin != nil && cfg.Jmax != nil && *cfg.Jmax == maxMessageSize-1 &&
		*cfg.Jmin == *cfg.Jmax && (cfg.Jc == nil || *cfg.Jc != 0) {
		return fmt.Errorf("wgtypes: Jmin = Jmax = %d is too large (the kernel uses Jmax+1)", *cfg.Jmax)
	}
	if cfg.Jmin != nil && cfg.Jmax != nil && *cfg.Jmax != 0 && *cfg.Jmin > *cfg.Jmax {
		return fmt.Errorf("wgtypes: Jmin (%d) must be <= Jmax (%d)", *cfg.Jmin, *cfg.Jmax)
	}

	paddings := []struct {
		name    string
		v       *int
		msgSize int
	}{
		{"S1", cfg.S1, messageInitiationSize},
		{"S2", cfg.S2, messageResponseSize},
		{"S3", cfg.S3, messageCookieSize},
		{"S4", cfg.S4, messageTransportSize},
	}
	for _, p := range paddings {
		if p.v == nil {
			continue
		}
		if limit := maxMessageSize - p.msgSize; *p.v < 0 || *p.v > limit {
			return fmt.Errorf("wgtypes: %s must be 0-%d, got %d", p.name, limit, *p.v)
		}
	}

	type hRange struct {
		name, value string
		start, end  uint32
	}
	var headers []hRange
	for i, h := range []*string{cfg.H1, cfg.H2, cfg.H3, cfg.H4} {
		if h == nil {
			continue
		}
		name := fmt.Sprintf("H%d", i+1)
		start, end, err := ParseMagicHeader(*h)
		if err != nil {
			return fmt.Errorf("wgtypes: %s: %w", name, err)
		}
		for _, o := range headers {
			if start <= o.end && o.start <= end {
				return fmt.Errorf("wgtypes: %s (%s) and %s (%s) overlap", o.name, o.value, name, *h)
			}
		}
		headers = append(headers, hRange{name, *h, start, end})
	}

	for i, spec := range []*string{cfg.I1, cfg.I2, cfg.I3, cfg.I4, cfg.I5} {
		if spec == nil {
			continue
		}
		if _, err := InitPacketSize(*spec); err != nil {
			return fmt.Errorf("wgtypes: I%d: %w", i+1, err)
		}
	}

	return nil
}

// ParseMagicHeader parses an H1-H4 value, "N" or "N-M", the way the kernel
// does: decimal 32-bit numbers with N <= M. A single value N is the range N-N.
func ParseMagicHeader(s string) (start, end uint32, err error) {
	lo, hi, isRange := strings.Cut(s, "-")
	start, err = parseKernelUint32(lo)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid magic header %q", s)
	}
	end = start
	if isRange {
		if end, err = parseKernelUint32(hi); err != nil {
			return 0, 0, fmt.Errorf("invalid magic header %q", s)
		}
	}
	if start > end {
		return 0, 0, fmt.Errorf("magic header range %q: start is above end", s)
	}
	return start, end, nil
}

// parseKernelUint32 accepts what the kernel's kstrtouint(s, 10) accepts.
func parseKernelUint32(s string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSuffix(s, "\n"), "+"), 10, 32)
	return uint32(v), err
}

// InitPacketSize parses an I1-I5 description the way the kernel does and
// returns the size of the packet it produces. Text outside <...> is ignored.
// Tags: <b 0xHEX> literal bytes, <c> packet counter and <t> unix time (4
// bytes each), <r N> random bytes, <rc N> random letters, <rd N> random
// digits. The packet may not exceed 65535 bytes.
func InitPacketSize(spec string) (int, error) {
	size := 0
	rest := spec
	for {
		_, after, found := strings.Cut(rest, "<")
		if !found {
			return size, nil
		}
		// Like the kernel's strsep, an unterminated tag runs to the end.
		tag, next, _ := strings.Cut(after, ">")
		rest = next

		key, val, hasVal := strings.Cut(tag, " ")
		var n int
		switch key {
		case "b":
			hex, ok := strings.CutPrefix(val, "0x")
			if !hasVal || !ok || len(hex) == 0 || len(hex)%2 != 0 || !isHex(hex) {
				return 0, fmt.Errorf("<%s>: <b> needs hex bytes, e.g. <b 0xc0ff>", tag)
			}
			n = len(hex) / 2
		case "c", "t":
			if hasVal {
				return 0, fmt.Errorf("<%s>: <%s> takes no value", tag, key)
			}
			n = 4
		case "r", "rc", "rd":
			v, err := strconv.ParseInt(strings.TrimSuffix(val, "\n"), 10, 32)
			if !hasVal || err != nil || v <= 0 {
				return 0, fmt.Errorf("<%s>: <%s> needs a positive length", tag, key)
			}
			if v > maxMessageSize {
				return 0, fmt.Errorf("<%s>: packet would exceed %d bytes", tag, maxMessageSize)
			}
			n = int(v)
		default:
			return 0, fmt.Errorf("<%s>: unknown tag %q", tag, key)
		}
		if n > maxMessageSize-size {
			return 0, fmt.Errorf("packet would exceed %d bytes", maxMessageSize)
		}
		size += n
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}
