//go:build linux
// +build linux

package wglinux

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/awg-go/awgctrl-go/wgtypes"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// AmneziaWG Netlink attribute constants.
// Derived from amneziawg-linux-kernel-module/src/uapi/wireguard.h
const (
	WGDEVICE_A_JC   = 9
	WGDEVICE_A_JMIN = 10
	WGDEVICE_A_JMAX = 11
	WGDEVICE_A_S1   = 12
	WGDEVICE_A_S2   = 13
	WGDEVICE_A_H1   = 14
	WGDEVICE_A_H2   = 15
	WGDEVICE_A_H3   = 16
	WGDEVICE_A_H4   = 17
	// WGDEVICE_A_PEER = 18
	WGDEVICE_A_S3 = 19
	WGDEVICE_A_S4 = 20
	WGDEVICE_A_I1 = 21
	WGDEVICE_A_I2 = 22
	WGDEVICE_A_I3 = 23
	WGDEVICE_A_I4 = 24
	WGDEVICE_A_I5 = 25

	WGDEVICE_A_HEADER_PROTECTION_KEY    = 26
	WGDEVICE_A_CONTENT_PADDING_ADDITION = 27
	WGDEVICE_A_REKEY_AFTER_TIME         = 28
	WGDEVICE_A_REKEY_TIMEOUT            = 29
	WGDEVICE_A_REJECT_AFTER_TIME        = 30
	WGDEVICE_A_KEEPALIVE_TIMEOUT        = 31
	WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS   = 32
	WGDEVICE_A_RANDOM_TRAILERS          = 33
	WGDEVICE_A_DISABLE_COOKIES          = 34

	// WGPEER_A_ADVANCED_SECURITY is an NLA_FLAG attribute on the peer.
	// Kernel sends it when peer->advanced_security is true.
	// Value = 11 (UNSPEC=0, PUBLIC_KEY=1, PRESHARED_KEY=2, FLAGS=3,
	// ENDPOINT=4, PERSISTENT_KEEPALIVE=5, LAST_HANDSHAKE=6,
	// RX_BYTES=7, TX_BYTES=8, ALLOWEDIPS=9, PROTOCOL_VERSION=10,
	// ADVANCED_SECURITY=11)
	WGPEER_A_ADVANCED_SECURITY = 11

	// WGPEER_F_HAS_ADVANCED_SECURITY is always sent by the kernel in
	// WGPEER_A_FLAGS to indicate the device supports AWG. We must send
	// it back when configuring a peer with AdvancedSecurity=true.
	WGPEER_F_HAS_ADVANCED_SECURITY = 1 << 3
)

// configAttrs creates the required encoded netlink attributes to configure
// the device specified by name using the non-nil fields in cfg.
func configAttrs(name string, cfg wgtypes.Config, familyVersion uint8) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, name)

	if cfg.PrivateKey != nil {
		ae.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, (*cfg.PrivateKey)[:])
	}

	if cfg.ListenPort != nil {
		ae.Uint16(unix.WGDEVICE_A_LISTEN_PORT, uint16(*cfg.ListenPort))
	}

	if cfg.FirewallMark != nil {
		ae.Uint32(unix.WGDEVICE_A_FWMARK, uint32(*cfg.FirewallMark))
	}

	if cfg.ReplacePeers {
		ae.Uint32(unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)
	}

	// -------------------------------------------------------------------------
	// AmneziaWG specific attributes encoding.
	// We check if the fields are present in the config (not nil) and encode them.
	// -------------------------------------------------------------------------

	// Uint16 parameters
	if cfg.Jc != nil {
		ae.Uint16(WGDEVICE_A_JC, uint16(*cfg.Jc))
	}
	if cfg.Jmin != nil {
		ae.Uint16(WGDEVICE_A_JMIN, uint16(*cfg.Jmin))
	}
	if cfg.Jmax != nil {
		ae.Uint16(WGDEVICE_A_JMAX, uint16(*cfg.Jmax))
	}

	if cfg.S1 != nil {
		ae.Uint16(WGDEVICE_A_S1, uint16(*cfg.S1))
	}
	if cfg.S2 != nil {
		ae.Uint16(WGDEVICE_A_S2, uint16(*cfg.S2))
	}
	if cfg.S3 != nil {
		ae.Uint16(WGDEVICE_A_S3, uint16(*cfg.S3))
	}
	if cfg.S4 != nil {
		ae.Uint16(WGDEVICE_A_S4, uint16(*cfg.S4))
	}

	// String parameters (Magic Headers)
	encodeHField := func(attr uint16, val *string) error {
		if val == nil {
			return nil
		}
		switch {
		case familyVersion >= 3:
			v, err := uintRangeStringToUint64(*val)
			if err != nil {
				return err
			}
			ae.Uint64(attr, v)
		case familyVersion >= 2:
			ae.String(attr, *val)
		default:
			v, err := uintRangeStringToUint32(*val)
			if err != nil {
				return err
			}
			ae.Uint32(attr, v)
		}
		return nil
	}

	if err := encodeHField(WGDEVICE_A_H1, cfg.H1); err != nil {
		return nil, err
	}
	if err := encodeHField(WGDEVICE_A_H2, cfg.H2); err != nil {
		return nil, err
	}
	if err := encodeHField(WGDEVICE_A_H3, cfg.H3); err != nil {
		return nil, err
	}
	if err := encodeHField(WGDEVICE_A_H4, cfg.H4); err != nil {
		return nil, err
	}

	// String parameters (Custom Packets)
	if cfg.I1 != nil {
		ae.String(WGDEVICE_A_I1, *cfg.I1)
	}
	if cfg.I2 != nil {
		ae.String(WGDEVICE_A_I2, *cfg.I2)
	}
	if cfg.I3 != nil {
		ae.String(WGDEVICE_A_I3, *cfg.I3)
	}
	if cfg.I4 != nil {
		ae.String(WGDEVICE_A_I4, *cfg.I4)
	}
	if cfg.I5 != nil {
		ae.String(WGDEVICE_A_I5, *cfg.I5)
	}

	// --- AmneziaWG 3.0 Specific Configuration ---
	if cfg.HeaderProtectionKey != nil {
		ae.Bytes(WGDEVICE_A_HEADER_PROTECTION_KEY, (*cfg.HeaderProtectionKey)[:])
	}
	if cfg.ContentPaddingAddition != nil {
		ae.Uint32(WGDEVICE_A_CONTENT_PADDING_ADDITION, uint32(*cfg.ContentPaddingAddition))
	}
	if cfg.RekeyAfterTime != nil {
		ae.Uint32(WGDEVICE_A_REKEY_AFTER_TIME, uint32(*cfg.RekeyAfterTime))
	}
	if cfg.RekeyTimeout != nil {
		ae.Uint32(WGDEVICE_A_REKEY_TIMEOUT, uint32(*cfg.RekeyTimeout))
	}
	if cfg.RejectAfterTime != nil {
		ae.Uint32(WGDEVICE_A_REJECT_AFTER_TIME, uint32(*cfg.RejectAfterTime))
	}
	if cfg.KeepaliveTimeout != nil {
		ae.Uint32(WGDEVICE_A_KEEPALIVE_TIMEOUT, uint32(*cfg.KeepaliveTimeout))
	}
	if cfg.MaxHandshakeAttempts != nil {
		ae.Uint32(WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, uint32(*cfg.MaxHandshakeAttempts))
	}
	if cfg.RandomTrailers != nil {
		var v uint8
		if *cfg.RandomTrailers {
			v = 1
		}
		ae.Uint8(WGDEVICE_A_RANDOM_TRAILERS, v)
	}
	if cfg.DisableCookies != nil {
		var v uint8
		if *cfg.DisableCookies {
			v = 1
		}
		ae.Uint8(WGDEVICE_A_DISABLE_COOKIES, v)
	}
	// -------------------------------------------------------------------------

	// Only apply peer attributes if necessary.
	if len(cfg.Peers) > 0 {
		ae.Nested(unix.WGDEVICE_A_PEERS, func(nae *netlink.AttributeEncoder) error {
			// Netlink arrays use type as an array index.
			for i, p := range cfg.Peers {
				nae.Nested(uint16(i), encodePeer(p))
			}

			return nil
		})
	}

	return ae.Encode()
}

// ipBatchChunk is a tunable allowed IP batch limit per peer.
//
// Because we don't necessarily know how much space a given peer will occupy,
// we play it safe and use a reasonably small value.  Note that this constant
// is used both in this package and tests, so be aware when making changes.
const ipBatchChunk = 256

// peerBatchChunk specifies the number of peers that can appear in a
// configuration before we start splitting it into chunks.
const peerBatchChunk = 32

// shouldBatch determines if a configuration is sufficiently complex that it
// should be split into batches.
func shouldBatch(cfg wgtypes.Config) bool {
	if len(cfg.Peers) > peerBatchChunk {
		return true
	}

	var ips int
	for _, p := range cfg.Peers {
		ips += len(p.AllowedIPs)
	}

	return ips > ipBatchChunk
}

// buildBatches produces a batch of configs from a single config, if needed.
func buildBatches(cfg wgtypes.Config) []wgtypes.Config {
	// Is this a small configuration; no need to batch?
	if !shouldBatch(cfg) {
		return []wgtypes.Config{cfg}
	}

	// Use most fields of cfg for our "base" configuration, and only differ
	// peers in each batch.
	base := cfg
	base.Peers = nil

	// AmneziaWG device parameters (Jc, Jmin, H1...) should only be sent in
	// the first batch. Subsequent batches only carry peer deltas.
	baseAWG := cfg
	baseAWG.Peers = nil

	// Strip AWG params from the template used for batches[1..N].
	base.Jc = nil
	base.Jmin = nil
	base.Jmax = nil
	base.S1 = nil
	base.S2 = nil
	base.S3 = nil
	base.S4 = nil
	base.H1 = nil
	base.H2 = nil
	base.H3 = nil
	base.H4 = nil
	base.I1 = nil
	base.I2 = nil
	base.I3 = nil
	base.I4 = nil
	base.I5 = nil

	base.HeaderProtectionKey = nil
	base.ContentPaddingAddition = nil
	base.RekeyAfterTime = nil
	base.RekeyTimeout = nil
	base.RejectAfterTime = nil
	base.KeepaliveTimeout = nil
	base.MaxHandshakeAttempts = nil
	base.RandomTrailers = nil
	base.DisableCookies = nil

	// Track the known peers so that peer IPs are not replaced if a single
	// peer has its allowed IPs split into multiple batches.
	knownPeers := make(map[wgtypes.Key]struct{})

	batches := make([]wgtypes.Config, 0)
	firstBatch := true
	for _, p := range cfg.Peers {
		// Iterate until no more allowed IPs.
		var done bool
		for !done {
			// AWG device params go only in the very first batch; all
			// subsequent batches (including later chunks of the same
			// peer) use the stripped base template.
			var batch wgtypes.Config
			if firstBatch {
				batch = baseAWG
				firstBatch = false
			} else {
				batch = base
			}
			var tmp []net.IPNet
			if len(p.AllowedIPs) < ipBatchChunk {
				// IPs all fit within a batch; we are done.
				tmp = make([]net.IPNet, len(p.AllowedIPs))
				copy(tmp, p.AllowedIPs)
				done = true
			} else {
				// IPs are larger than a single batch, copy a batch out and
				// advance the cursor.
				tmp = make([]net.IPNet, ipBatchChunk)
				copy(tmp, p.AllowedIPs[:ipBatchChunk])

				p.AllowedIPs = p.AllowedIPs[ipBatchChunk:]

				if len(p.AllowedIPs) == 0 {
					// IPs ended on a batch boundary; no more IPs left so end
					// iteration after this loop.
					done = true
				}
			}

			pcfg := wgtypes.PeerConfig{
				// PublicKey denotes the peer and must be present.
				PublicKey: p.PublicKey,

				// Apply the update only flag to every chunk to ensure
				// consistency between batches when the kernel module processes
				// them.
				UpdateOnly: p.UpdateOnly,

				// It'd be a bit weird to have a remove peer message with many
				// IPs, but just in case, add this to every peer's message.
				Remove: p.Remove,

				// AdvancedSecurity must be present in every chunk so the
				// kernel enables AWG obfuscation regardless of batch order.
				AdvancedSecurity: p.AdvancedSecurity,

				// The IPs for this chunk.
				AllowedIPs: tmp,
			}

			// Only pass certain fields on the first occurrence of a peer, so
			// that subsequent IPs won't be wiped out and space isn't wasted.
			if _, ok := knownPeers[p.PublicKey]; !ok {
				knownPeers[p.PublicKey] = struct{}{}

				pcfg.PresharedKey = p.PresharedKey
				pcfg.Endpoint = p.Endpoint
				pcfg.PersistentKeepaliveInterval = p.PersistentKeepaliveInterval

				// Important: do not move or appending peers won't work.
				pcfg.ReplaceAllowedIPs = p.ReplaceAllowedIPs
			}

			// Add a peer configuration to this batch and keep going.
			batch.Peers = []wgtypes.PeerConfig{pcfg}
			batches = append(batches, batch)
		}
	}

	// ReplacePeers is only honoured in the first batch. Subsequent batches
	// must have it cleared; otherwise the kernel would discard all peers
	// added by earlier batches every time a new batch arrives. This is safe
	// because the first batch already told the kernel to start fresh.
	for i := range batches {
		if i > 0 {
			batches[i].ReplacePeers = false
		}
	}

	return batches
}

// encodePeer returns a function to encode PeerConfig nested attributes.
func encodePeer(p wgtypes.PeerConfig) func(ae *netlink.AttributeEncoder) error {
	return func(ae *netlink.AttributeEncoder) error {
		ae.Bytes(unix.WGPEER_A_PUBLIC_KEY, p.PublicKey[:])

		// Flags are stored in a single attribute.
		var flags uint32
		if p.Remove {
			flags |= unix.WGPEER_F_REMOVE_ME
		}
		if p.ReplaceAllowedIPs {
			flags |= unix.WGPEER_F_REPLACE_ALLOWEDIPS
		}
		if p.UpdateOnly {
			flags |= unix.WGPEER_F_UPDATE_ONLY
		}
		// WGPEER_F_HAS_ADVANCED_SECURITY must be set whenever we want
		// the kernel to pay attention to WGPEER_A_ADVANCED_SECURITY.
		if p.AdvancedSecurity {
			flags |= WGPEER_F_HAS_ADVANCED_SECURITY
		}
		if flags != 0 {
			ae.Uint32(unix.WGPEER_A_FLAGS, flags)
		}

		// Send the NLA_FLAG attribute to actually enable AWG on this peer.
		// NLA_FLAG is encoded as a zero-length attribute.
		if p.AdvancedSecurity {
			ae.Bytes(uint16(WGPEER_A_ADVANCED_SECURITY), []byte{})
		}

		if p.PresharedKey != nil {
			ae.Bytes(unix.WGPEER_A_PRESHARED_KEY, (*p.PresharedKey)[:])
		}

		if p.Endpoint != nil {
			ae.Do(unix.WGPEER_A_ENDPOINT, encodeSockaddr(*p.Endpoint))
		}

		if p.PersistentKeepaliveInterval != nil {
			ae.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, uint16(p.PersistentKeepaliveInterval.Seconds()))
		}

		// Only apply allowed IPs if necessary.
		if len(p.AllowedIPs) > 0 {
			ae.Nested(unix.WGPEER_A_ALLOWEDIPS, encodeAllowedIPs(p.AllowedIPs))
		}

		return nil
	}
}

// encodeSockaddr returns a function which encodes a net.UDPAddr as raw
// sockaddr_in or sockaddr_in6 bytes.
func encodeSockaddr(endpoint net.UDPAddr) func() ([]byte, error) {
	return func() ([]byte, error) {
		if !isValidIP(endpoint.IP) {
			return nil, fmt.Errorf("wglinux: invalid endpoint IP: %s", endpoint.IP.String())
		}

		// Is this an IPv6 address?
		if isIPv6(endpoint.IP) {
			var addr [16]byte
			copy(addr[:], endpoint.IP.To16())

			sa := unix.RawSockaddrInet6{
				Family: unix.AF_INET6,
				Port:   sockaddrPort(endpoint.Port),
				Addr:   addr,
			}

			return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:], nil
		}

		// IPv4 address handling.
		var addr [4]byte
		copy(addr[:], endpoint.IP.To4())

		sa := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   sockaddrPort(endpoint.Port),
			Addr:   addr,
		}

		return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:], nil
	}
}

// encodeAllowedIPs returns a function to encode allowed IP nested attributes.
func encodeAllowedIPs(ipns []net.IPNet) func(ae *netlink.AttributeEncoder) error {
	return func(ae *netlink.AttributeEncoder) error {
		for i, ipn := range ipns {
			if !isValidIP(ipn.IP) {
				return fmt.Errorf("wglinux: invalid allowed IP: %s", ipn.IP.String())
			}

			family := uint16(unix.AF_INET6)
			if !isIPv6(ipn.IP) {
				// Make sure address is 4 bytes if IPv4.
				family = unix.AF_INET
				ipn.IP = ipn.IP.To4()
			}

			// Netlink arrays use type as an array index.
			ae.Nested(uint16(i), func(nae *netlink.AttributeEncoder) error {
				nae.Uint16(unix.WGALLOWEDIP_A_FAMILY, family)
				nae.Bytes(unix.WGALLOWEDIP_A_IPADDR, ipn.IP)

				ones, _ := ipn.Mask.Size()
				nae.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(ones))
				return nil
			})
		}

		return nil
	}
}

// isValidIP determines if IP is a valid IPv4 or IPv6 address.
func isValidIP(ip net.IP) bool {
	return ip.To16() != nil
}

// isIPv6 determines if IP is a valid IPv6 address.
func isIPv6(ip net.IP) bool {
	return isValidIP(ip) && ip.To4() == nil
}

// sockaddrPort interprets port as a big endian uint16 for use passing sockaddr
// structures to the kernel.
func sockaddrPort(port int) uint16 {
	return binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(port)))
}
