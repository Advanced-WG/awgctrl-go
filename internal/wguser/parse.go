package wguser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/awg-go/awgctrl-go/wgtypes"
)

// The WireGuard userspace configuration protocol is described here:
// https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation.

// getDevice gathers device information from a device specified by its path
// and returns a Device.
func (c *Client) getDevice(ctx context.Context, device string) (*wgtypes.Device, error) {
	conn, err := c.dial(ctx, device)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// If the context carries a deadline, propagate it to the connection
	// so that blocked reads/writes are cancelled.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	// Get information about this device.
	if _, err := io.WriteString(conn, "get=1\n\n"); err != nil {
		return nil, err
	}

	// Parse the device from the incoming data stream.
	d, err := parseDevice(conn)
	if err != nil {
		return nil, err
	}

	// TODO(mdlayher): populate interface index too?
	d.Name = deviceName(device)
	d.Type = wgtypes.Userspace

	return d, nil
}

// parseDevice parses a Device and its Peers from an io.Reader.
func parseDevice(r io.Reader) (*wgtypes.Device, error) {
	var dp deviceParser
	s := bufio.NewScanner(r)
	for s.Scan() {
		b := s.Bytes()
		if len(b) == 0 {
			// Empty line, done parsing.
			break
		}

		// All data is in key=value format.
		kvs := bytes.Split(b, []byte("="))
		if len(kvs) != 2 {
			return nil, fmt.Errorf("wguser: invalid key=value pair: %q", string(b))
		}

		dp.Parse(string(kvs[0]), string(kvs[1]))
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	return dp.Device()
}

// A deviceParser accumulates information about a Device and its Peers.
type deviceParser struct {
	d   wgtypes.Device
	err error

	parsePeers    bool
	peers         int
	hsSec, hsNano int
}

// Device returns a Device or any errors that were encountered while parsing
// a Device.
func (dp *deviceParser) Device() (*wgtypes.Device, error) {
	if dp.err != nil {
		return nil, dp.err
	}

	// Compute remaining fields of the Device now that all parsing is done.
	dp.d.PublicKey = dp.d.PrivateKey.PublicKey()

	return &dp.d, nil
}

// Parse parses a single key/value pair into fields of a Device.
func (dp *deviceParser) Parse(key, value string) {
	switch key {
	case "errno":
		// 0 indicates success, anything else returns an error number that matches
		// definitions from errno.h.
		if errno := dp.parseInt(value); errno != 0 {
			// TODO(mdlayher): return actual errno on Linux?
			dp.err = os.NewSyscallError("read", fmt.Errorf("wguser: errno=%d", errno))
			return
		}
	case "public_key":
		// We've either found the first peer or the next peer.  Stop parsing
		// Device fields and start parsing Peer fields, including the public
		// key indicated here.
		dp.parsePeers = true
		dp.peers++

		dp.hsSec = 0
		dp.hsNano = 0

		dp.d.Peers = append(dp.d.Peers, wgtypes.Peer{
			PublicKey: dp.parseKey(value),
		})
		return
	}

	// Are we parsing peer fields?
	if dp.parsePeers {
		dp.peerParse(key, value)
		return
	}

	// Device field parsing.
	switch key {
	case "private_key":
		dp.d.PrivateKey = dp.parseKey(value)
	case "listen_port":
		dp.d.ListenPort = dp.parseInt(value)
	case "fwmark":
		dp.d.FirewallMark = dp.parseInt(value)
	// AmneziaWG userspace daemon fields.
	case "jc":
		dp.d.Jc = dp.parseInt(value)
		dp.d.IsAmnezia = true
	case "jmin":
		dp.d.Jmin = dp.parseInt(value)
	case "jmax":
		dp.d.Jmax = dp.parseInt(value)
	case "s1":
		dp.d.S1 = dp.parseInt(value)
	case "s2":
		dp.d.S2 = dp.parseInt(value)
	case "s3":
		dp.d.S3 = dp.parseInt(value)
	case "s4":
		dp.d.S4 = dp.parseInt(value)
	case "h1":
		dp.d.H1 = value
	case "h2":
		dp.d.H2 = value
	case "h3":
		dp.d.H3 = value
	case "h4":
		dp.d.H4 = value
	case "i1":
		dp.d.I1 = value
	case "i2":
		dp.d.I2 = value
	case "i3":
		dp.d.I3 = value
	case "i4":
		dp.d.I4 = value
	case "i5":
		dp.d.I5 = value
	case "header_protection_key":
		dp.d.HeaderProtectionKey = dp.parseKey(value)
	case "content_padding_addition":
		dp.d.ContentPaddingAddition = dp.parseUintRange(value)
	case "rekey_after_time":
		dp.d.RekeyAfterTime = dp.parseUintRange(value)
	case "rekey_timeout":
		dp.d.RekeyTimeout = dp.parseUintRange(value)
	case "reject_after_time":
		dp.d.RejectAfterTime = dp.parseUintRange(value)
	case "keepalive_timeout":
		dp.d.KeepaliveTimeout = dp.parseUintRange(value)
	case "max_handshake_attempts":
		dp.d.MaxHandshakeAttempts = dp.parseUintRange(value)
	case "random_trailers":
		dp.d.RandomTrailers = value == "true"
	case "disable_cookies":
		dp.d.DisableCookies = value == "true"
	}
}

// curPeer returns the current Peer being parsed so its fields can be populated.
func (dp *deviceParser) curPeer() *wgtypes.Peer {
	return &dp.d.Peers[dp.peers-1]
}

// peerParse parses a key/value field into the current Peer.
func (dp *deviceParser) peerParse(key, value string) {
	p := dp.curPeer()
	switch key {
	case "preshared_key":
		p.PresharedKey = dp.parseKey(value)
	case "endpoint":
		p.Endpoint = dp.parseAddr(value)
	case "last_handshake_time_sec":
		dp.hsSec = dp.parseInt(value)
		if dp.hsSec > 0 || dp.hsNano > 0 {
			p.LastHandshakeTime = time.Unix(int64(dp.hsSec), int64(dp.hsNano))
		}
	case "last_handshake_time_nsec":
		dp.hsNano = dp.parseInt(value)
		if dp.hsSec > 0 || dp.hsNano > 0 {
			p.LastHandshakeTime = time.Unix(int64(dp.hsSec), int64(dp.hsNano))
		}
	case "tx_bytes":
		p.TransmitBytes = dp.parseInt64(value)
	case "rx_bytes":
		p.ReceiveBytes = dp.parseInt64(value)
	case "persistent_keepalive_interval":
		p.PersistentKeepaliveInterval = time.Duration(dp.parseInt(value)) * time.Second
	case "allowed_ip":
		cidr := dp.parseCIDR(value)
		if cidr != nil {
			p.AllowedIPs = append(p.AllowedIPs, *cidr)
		}
	case "protocol_version":
		p.ProtocolVersion = dp.parseInt(value)
	}
}

// parseKey parses a Key from a hex string.
func (dp *deviceParser) parseKey(s string) wgtypes.Key {
	if dp.err != nil {
		return wgtypes.Key{}
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		dp.err = err
		return wgtypes.Key{}
	}

	key, err := wgtypes.NewKey(b)
	if err != nil {
		dp.err = err
		return wgtypes.Key{}
	}

	return key
}

// parseInt parses an integer from a string.
func (dp *deviceParser) parseInt(s string) int {
	if dp.err != nil {
		return 0
	}

	v, err := strconv.Atoi(s)
	if err != nil {
		dp.err = err
		return 0
	}

	return v
}

// parseUintRange parses an AWG 3 UAPI range ("10" or "10-100").
func (dp *deviceParser) parseUintRange(s string) wgtypes.UintRange {
	if dp.err != nil {
		return wgtypes.UintRange{}
	}
	r, err := wgtypes.ParseUintRange(s)
	if err != nil {
		dp.err = err
		return wgtypes.UintRange{}
	}
	return r
}

// parseInt64 parses an int64 from a string.
func (dp *deviceParser) parseInt64(s string) int64 {
	if dp.err != nil {
		return 0
	}

	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		dp.err = err
		return 0
	}

	return v
}

// parseAddr parses a UDP address from a string.
func (dp *deviceParser) parseAddr(s string) *net.UDPAddr {
	if dp.err != nil {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		dp.err = err
		return nil
	}

	return addr
}

// parseInt parses an address CIDR from a string.
func (dp *deviceParser) parseCIDR(s string) *net.IPNet {
	if dp.err != nil {
		return nil
	}

	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		dp.err = err
		return nil
	}

	return cidr
}
