package wgtypes

import (
	"fmt"
	"strings"
)

// LIB-06: printing a Device, Peer, Config or PeerConfig with %v, %+v or %#v
// (a log line, an error message) wrote the private and preshared keys in
// clear, as upstream wgctrl does. These methods print everything else and
// "(hidden)" in place of those keys. Key.String is unchanged: a single Key
// prints as base64, which is what public keys need.

const hiddenKey = "(hidden)"

// hide replaces each set key in s, in both the base64 form of Key.String and
// the Go syntax of %#v, with "(hidden)".
func hide(s string, keys ...*Key) string {
	for _, k := range keys {
		if k == nil || *k == (Key{}) {
			continue
		}
		s = strings.ReplaceAll(s, fmt.Sprintf("%#v", [KeyLen]byte(*k)), hiddenKey)
		s = strings.ReplaceAll(s, k.String(), hiddenKey)
	}
	return s
}

// String prints the device without its private key.
func (d Device) String() string {
	type device Device // no methods: no recursion
	return hide(fmt.Sprintf("%+v", device(d)), &d.PrivateKey)
}

// GoString is String in Go syntax.
func (d Device) GoString() string {
	type device Device
	return hide(fmt.Sprintf("%#v", device(d)), &d.PrivateKey)
}

// String prints the peer without its preshared key.
func (p Peer) String() string {
	type peer Peer
	return hide(fmt.Sprintf("%+v", peer(p)), &p.PresharedKey)
}

// GoString is String in Go syntax.
func (p Peer) GoString() string {
	type peer Peer
	return hide(fmt.Sprintf("%#v", peer(p)), &p.PresharedKey)
}

// String prints the configuration without its private key.
func (c Config) String() string {
	type config Config
	return hide(fmt.Sprintf("%+v", config(c)), c.PrivateKey)
}

// GoString is String in Go syntax.
func (c Config) GoString() string {
	type config Config
	return hide(fmt.Sprintf("%#v", config(c)), c.PrivateKey)
}

// String prints the peer configuration without its preshared key.
func (p PeerConfig) String() string {
	type peerConfig PeerConfig
	return hide(fmt.Sprintf("%+v", peerConfig(p)), p.PresharedKey)
}

// GoString is String in Go syntax.
func (p PeerConfig) GoString() string {
	type peerConfig PeerConfig
	return hide(fmt.Sprintf("%#v", peerConfig(p)), p.PresharedKey)
}
