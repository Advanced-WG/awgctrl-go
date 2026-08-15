//go:build linux
// +build linux

package wglinux

import (
	"context"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/advanced-wg/awgctrl-go/internal/wgtest"
	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mikioh/ipaddr"
	"golang.org/x/sys/unix"
)

func TestLinuxClientConfigureDevice(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	tests := []struct {
		name  string
		cfg   wgtypes.Config
		attrs []netlink.Attribute
		ok    bool
	}{
		{
			name: "bad peer endpoint",
			cfg: wgtypes.Config{
				Peers: []wgtypes.PeerConfig{{
					Endpoint: &net.UDPAddr{
						IP: net.IP{0xff},
					},
				}},
			},
		},
		{
			name: "bad peer allowed IP",
			cfg: wgtypes.Config{
				Peers: []wgtypes.PeerConfig{{
					AllowedIPs: []net.IPNet{{
						IP: net.IP{0xff},
					}},
				}},
			},
		},
		{
			name: "ok, none",
			attrs: []netlink.Attribute{
				nameAttr,
			},
			ok: true,
		},
		{
			name: "ok, all",
			cfg: wgtypes.Config{
				PrivateKey:   keyPtr(wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
				ListenPort:   intPtr(12912),
				FirewallMark: intPtr(0),
				ReplacePeers: true,
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         wgtest.MustHexKey("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
						PresharedKey:      keyPtr(wgtest.MustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
						Endpoint:          wgtest.MustUDPAddr("[abcd:23::33%2]:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.4/32"),
						},
					},
					{
						PublicKey:                   wgtest.MustHexKey("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
						UpdateOnly:                  true,
						Endpoint:                    wgtest.MustUDPAddr("182.122.22.19:3233"),
						PersistentKeepaliveInterval: durPtr(111 * time.Second),
						ReplaceAllowedIPs:           true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.6/32"),
						},
					},
					{
						PublicKey:         wgtest.MustHexKey("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
						Endpoint:          wgtest.MustUDPAddr("5.152.198.39:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.10/32"),
							wgtest.MustCIDR("192.168.4.11/32"),
						},
					},
					{
						PublicKey: wgtest.MustHexKey("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
						Remove:    true,
					},
				},
			},
			attrs: []netlink.Attribute{
				nameAttr,
				{
					Type: unix.WGDEVICE_A_PRIVATE_KEY,
					Data: keyBytes("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"),
				},
				{
					Type: unix.WGDEVICE_A_LISTEN_PORT,
					Data: nlenc.Uint16Bytes(12912),
				},
				{
					Type: unix.WGDEVICE_A_FWMARK,
					Data: nlenc.Uint32Bytes(0),
				},
				{
					Type: unix.WGDEVICE_A_FLAGS,
					Data: nlenc.Uint32Bytes(unix.WGDEVICE_F_REPLACE_PEERS),
				},
				{
					Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
					Data: m([]netlink.Attribute{
						{
							Type: netlink.Nested,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS),
								},
								{
									Type: unix.WGPEER_A_PRESHARED_KEY,
									Data: keyBytes("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52"),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
										Family: unix.AF_INET6,
										Addr: [16]byte{
											0xab, 0xcd, 0x00, 0x23,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x33,
										},
										Port: sockaddrPort(51820),
									})))[:],
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.4/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 1,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{182, 122, 22, 19},
										Port:   sockaddrPort(3233),
									})))[:],
								},
								{
									Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
									Data: nlenc.Uint16Bytes(111),
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.6/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 2,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{5, 152, 198, 39},
										Port:   sockaddrPort(51820),
									})))[:],
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.10/32"),
										wgtest.MustCIDR("192.168.4.11/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 3,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REMOVE_ME),
								},
							}...),
						},
					}...),
				},
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				attrs, err := netlink.UnmarshalAttributes(greq.Data)
				if err != nil {
					return nil, err
				}

				if diff := diffAttrs(tt.attrs, attrs); diff != "" {
					t.Fatalf("unexpected request attributes (-want +got):\n%s", diff)
				}

				// Data currently unused; send a message to acknowledge request.
				return []genetlink.Message{{}}, nil
			}

			c := testClient(t, configureHandler(fn))
			defer c.Close()

			err := c.ConfigureDevice(context.Background(), okName, tt.cfg)

			if tt.ok && err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestLinuxClientConfigureDeviceLargePeerIPChunks(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	var (
		peerA    = wgtest.MustPublicKey()
		peerAIPs = generateIPs(ipBatchChunk + 1)

		peerB    = wgtest.MustPublicKey()
		peerBIPs = generateIPs(ipBatchChunk / 2)

		peerC    = wgtest.MustPublicKey()
		peerCIPs = generateIPs(ipBatchChunk * 3)

		peerD = wgtest.MustPublicKey()
	)

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerA,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,

				AllowedIPs: peerAIPs,
			},
			{
				PublicKey:         peerB,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        peerBIPs,
			},
			{
				PublicKey:         peerC,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        peerCIPs,
			},
			{
				PublicKey: peerD,
				Remove:    true,
			},
		},
	}

	var allAttrs []netlink.Attribute
	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil {
			return nil, err
		}

		allAttrs = append(allAttrs, attrs...)

		// Data currently unused; send a message to acknowledge request.
		return []genetlink.Message{{}}, nil
	}

	c := testClient(t, configureHandler(fn))
	defer c.Close()

	if err := c.ConfigureDevice(context.Background(), okName, cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	want := []netlink.Attribute{
		// First peer, first chunk.
		nameAttr,
		{
			Type: unix.WGDEVICE_A_FLAGS,
			Data: nlenc.Uint32Bytes(unix.WGDEVICE_F_REPLACE_PEERS),
		},
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerA[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerAIPs[:ipBatchChunk]),
					},
				}...),
			}),
		},
		// First peer, final chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerA[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerAIPs[ipBatchChunk:]),
					},
				}...),
			}),
		},
		// Second peer, only chunk.
		nameAttr,
		// This is not the first peer; don't replace existing peers.
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerB[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerBIPs),
					},
				}...),
			}),
		},
		// Third peer, first chunk.
		nameAttr,
		// This is not the first peer; don't replace existing peers.
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[:ipBatchChunk]),
					},
				}...),
			}),
		},
		// Third peer, second chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[ipBatchChunk : ipBatchChunk*2]),
					},
				}...),
			}),
		},
		// Third peer, final chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[ipBatchChunk*2:]),
					},
				}...),
			}),
		},
		// Fourth peer, only chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerD[:],
					},
					// Not first chunk; don't replace IPs.
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REMOVE_ME),
					},
				}...),
			}),
		},
	}

	if diff := diffAttrs(want, allAttrs); diff != "" {
		t.Fatalf("unexpected final attributes (-want +got):\n%s", diff)
	}
}

// TestLinuxClientConfigureDeviceAWGParams verifies that AmneziaWG device
// parameters (Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I5) are correctly encoded
// as netlink attributes when configuring a device. Tests AWG 3 encoding.
func TestLinuxClientConfigureDeviceAWGParams(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	strPtr := func(s string) *string { return &s }

	cfg := wgtypes.Config{
		Jc:   intPtr(5),
		Jmin: intPtr(100),
		Jmax: intPtr(200),
		S1:   intPtr(30),
		S2:   intPtr(40),
		S3:   intPtr(50),
		S4:   intPtr(8),
		H1:   strPtr("150000000-200000000"),
		H2:   strPtr("250000000-300000000"),
		H3:   strPtr("350000000-400000000"),
		H4:   strPtr("450000000-500000000"),
		I1:   strPtr("<r 20>"),
		I2:   strPtr("<r 15>"),
		I3:   strPtr("<r 12>"),
		I4:   strPtr("<r 18>"),
		I5:   strPtr("<r 14>"),
	}

	wantAttrs := []netlink.Attribute{
		nameAttr,
		{Type: WGDEVICE_A_JC, Data: nlenc.Uint16Bytes(5)},
		{Type: WGDEVICE_A_JMIN, Data: nlenc.Uint16Bytes(100)},
		{Type: WGDEVICE_A_JMAX, Data: nlenc.Uint16Bytes(200)},
		{Type: WGDEVICE_A_S1, Data: nlenc.Uint16Bytes(30)},
		{Type: WGDEVICE_A_S2, Data: nlenc.Uint16Bytes(40)},
		{Type: WGDEVICE_A_S3, Data: nlenc.Uint16Bytes(50)},
		{Type: WGDEVICE_A_S4, Data: nlenc.Uint16Bytes(8)},
		{Type: WGDEVICE_A_H1, Data: nlenc.Uint64Bytes(uint64(200000000)<<32 | 150000000)},
		{Type: WGDEVICE_A_H2, Data: nlenc.Uint64Bytes(uint64(300000000)<<32 | 250000000)},
		{Type: WGDEVICE_A_H3, Data: nlenc.Uint64Bytes(uint64(400000000)<<32 | 350000000)},
		{Type: WGDEVICE_A_H4, Data: nlenc.Uint64Bytes(uint64(500000000)<<32 | 450000000)},
		{Type: WGDEVICE_A_I1, Data: nlenc.Bytes("<r 20>")},
		{Type: WGDEVICE_A_I2, Data: nlenc.Bytes("<r 15>")},
		{Type: WGDEVICE_A_I3, Data: nlenc.Bytes("<r 12>")},
		{Type: WGDEVICE_A_I4, Data: nlenc.Bytes("<r 18>")},
		{Type: WGDEVICE_A_I5, Data: nlenc.Bytes("<r 14>")},
	}

	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil {
			return nil, err
		}

		if diff := diffAttrs(wantAttrs, attrs); diff != "" {
			t.Fatalf("unexpected AWG config attributes (-want +got):\n%s", diff)
		}

		return []genetlink.Message{{}}, nil
	}

	c := testClientWithVersion(t, 3, configureHandler(fn))
	defer c.Close()

	if err := c.ConfigureDevice(context.Background(), okName, cfg); err != nil {
		t.Fatalf("failed to configure AWG device: %v", err)
	}
}

func TestLinuxClientConfigureDeviceAWGParamsV2(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	cfg := wgtypes.Config{
		H1: strPtr("150000000-200000000"),
	}
	wantAttrs := []netlink.Attribute{
		{Type: unix.WGDEVICE_A_IFNAME, Data: nlenc.Bytes(okName)},
		{Type: WGDEVICE_A_H1, Data: nlenc.Bytes("150000000-200000000")},
	}
	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil { return nil, err }
		if diff := diffAttrs(wantAttrs, attrs); diff != "" {
			t.Fatalf("unexpected AWG V2 config attributes (-want +got):\n%s", diff)
		}
		return []genetlink.Message{{}}, nil
	}
	c := testClientWithVersion(t, 2, configureHandler(fn))
	defer c.Close()
	if err := c.ConfigureDevice(context.Background(), okName, cfg); err != nil {
		t.Fatalf("failed to configure AWG device (V2): %v", err)
	}
}

func TestLinuxClientConfigureDeviceAWGParamsV1(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	cfg := wgtypes.Config{
		H1: strPtr("150000000-200000000"),
	}
	wantAttrs := []netlink.Attribute{
		{Type: unix.WGDEVICE_A_IFNAME, Data: nlenc.Bytes(okName)},
		{Type: WGDEVICE_A_H1, Data: nlenc.Uint32Bytes(150000000)},
	}
	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil { return nil, err }
		if diff := diffAttrs(wantAttrs, attrs); diff != "" {
			t.Fatalf("unexpected AWG V1 config attributes (-want +got):\n%s", diff)
		}
		return []genetlink.Message{{}}, nil
	}
	c := testClientWithVersion(t, 1, configureHandler(fn))
	defer c.Close()
	if err := c.ConfigureDevice(context.Background(), okName, cfg); err != nil {
		t.Fatalf("failed to configure AWG device (V1): %v", err)
	}
}

// TestLinuxClientConfigureDeviceAWGPartial verifies that only non-nil AWG
// parameters are encoded — nil fields must be omitted.
func TestLinuxClientConfigureDeviceAWGPartial(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	cfg := wgtypes.Config{
		Jc:   intPtr(3),
		Jmin: intPtr(80),
		// Jmax intentionally nil — should not appear.
	}

	wantAttrs := []netlink.Attribute{
		nameAttr,
		{Type: WGDEVICE_A_JC, Data: nlenc.Uint16Bytes(3)},
		{Type: WGDEVICE_A_JMIN, Data: nlenc.Uint16Bytes(80)},
	}

	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil {
			return nil, err
		}

		if diff := diffAttrs(wantAttrs, attrs); diff != "" {
			t.Fatalf("unexpected partial AWG config attributes (-want +got):\n%s", diff)
		}

		return []genetlink.Message{{}}, nil
	}

	c := testClient(t, configureHandler(fn))
	defer c.Close()

	if err := c.ConfigureDevice(context.Background(), okName, cfg); err != nil {
		t.Fatalf("failed to configure device with partial AWG params: %v", err)
	}
}

// TestLinuxClientConfigureDevicePeerAdvancedSecurity verifies that the
// AdvancedSecurity peer flag is correctly encoded as WGPEER_F_HAS_ADVANCED_SECURITY
// in WGPEER_A_FLAGS and as a zero-length WGPEER_A_ADVANCED_SECURITY NLA_FLAG.
func TestLinuxClientConfigureDevicePeerAdvancedSecurity(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	peerKey := wgtest.MustPublicKey()

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:        peerKey,
				AdvancedSecurity: true,
			},
		},
	}

	wantAttrs := []netlink.Attribute{
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerKey[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(WGPEER_F_HAS_ADVANCED_SECURITY),
					},
					{
						// NLA_FLAG: zero-length attribute.
						Type: uint16(WGPEER_A_ADVANCED_SECURITY),
						Data: []byte{},
					},
				}...),
			}),
		},
	}

	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil {
			return nil, err
		}

		if diff := diffAttrs(wantAttrs, attrs); diff != "" {
			t.Fatalf("unexpected AdvancedSecurity attributes (-want +got):\n%s", diff)
		}

		return []genetlink.Message{{}}, nil
	}

	c := testClient(t, configureHandler(fn))
	defer c.Close()

	if err := c.ConfigureDevice(context.Background(), okName, cfg); err != nil {
		t.Fatalf("failed to configure peer with AdvancedSecurity: %v", err)
	}
}

// TestLinuxClientConfigureDevicePeerNoAdvancedSecurity verifies that when
// AdvancedSecurity is false, neither WGPEER_F_HAS_ADVANCED_SECURITY nor
// WGPEER_A_ADVANCED_SECURITY are present.
func TestLinuxClientConfigureDevicePeerNoAdvancedSecurity(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	peerKey := wgtest.MustPublicKey()

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:        peerKey,
				AdvancedSecurity: false,
			},
		},
	}

	// No flags, no ADVANCED_SECURITY attribute expected.
	wantAttrs := []netlink.Attribute{
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m(netlink.Attribute{
					Type: unix.WGPEER_A_PUBLIC_KEY,
					Data: peerKey[:],
				}),
			}),
		},
	}

	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil {
			return nil, err
		}

		if diff := diffAttrs(wantAttrs, attrs); diff != "" {
			t.Fatalf("unexpected attributes when AdvancedSecurity=false (-want +got):\n%s", diff)
		}

		return []genetlink.Message{{}}, nil
	}

	c := testClient(t, configureHandler(fn))
	defer c.Close()

	if err := c.ConfigureDevice(context.Background(), okName, cfg); err != nil {
		t.Fatalf("failed to configure peer without AdvancedSecurity: %v", err)
	}
}

// TestBuildBatchesAWGParamsFirstBatchOnly verifies that AWG device parameters
// (Jc, Jmin, ..., I5) are only present in the first batch and stripped from
// subsequent batches when a large configuration is split.
func TestBuildBatchesAWGParamsFirstBatchOnly(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	// Create a config with AWG params and enough IPs to trigger batching.
	peerKey := wgtest.MustPublicKey()
	cfg := wgtypes.Config{
		Jc:   intPtr(5),
		Jmin: intPtr(100),
		Jmax: intPtr(200),
		S1:   intPtr(30),
		S2:   intPtr(40),
		S3:   intPtr(50),
		S4:   intPtr(8),
		H1:   strPtr("111-222"),
		H2:   strPtr("333-444"),
		H3:   strPtr("555-666"),
		H4:   strPtr("777-888"),
		I1:   strPtr("<r 10>"),
		I2:   strPtr("<r 11>"),
		I3:   strPtr("<r 12>"),
		I4:   strPtr("<r 13>"),
		I5:   strPtr("<r 14>"),
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:  peerKey,
				AllowedIPs: generateIPs(ipBatchChunk + 1),
			},
		},
	}

	batches := buildBatches(cfg)
	if len(batches) < 2 {
		t.Fatalf("expected at least 2 batches, got %d", len(batches))
	}

	// First batch must have all AWG params.
	first := batches[0]
	if first.Jc == nil || *first.Jc != 5 {
		t.Error("first batch: Jc missing or wrong")
	}
	if first.H1 == nil || *first.H1 != "111-222" {
		t.Error("first batch: H1 missing or wrong")
	}
	if first.I1 == nil || *first.I1 != "<r 10>" {
		t.Error("first batch: I1 missing or wrong")
	}

	// Subsequent batches must NOT have AWG params.
	for i := 1; i < len(batches); i++ {
		b := batches[i]
		if b.Jc != nil || b.Jmin != nil || b.Jmax != nil {
			t.Errorf("batch %d: Jc/Jmin/Jmax should be nil", i)
		}
		if b.S1 != nil || b.S2 != nil || b.S3 != nil || b.S4 != nil {
			t.Errorf("batch %d: S1-S4 should be nil", i)
		}
		if b.H1 != nil || b.H2 != nil || b.H3 != nil || b.H4 != nil {
			t.Errorf("batch %d: H1-H4 should be nil", i)
		}
		if b.I1 != nil || b.I2 != nil || b.I3 != nil || b.I4 != nil || b.I5 != nil {
			t.Errorf("batch %d: I1-I5 should be nil", i)
		}
	}
}

// TestBuildBatchesAdvancedSecurityPreserved verifies that the AdvancedSecurity
// flag on peers is preserved in all batch chunks for that peer.
func TestBuildBatchesAdvancedSecurityPreserved(t *testing.T) {
	peerKey := wgtest.MustPublicKey()
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:        peerKey,
				AdvancedSecurity: true,
				AllowedIPs:       generateIPs(ipBatchChunk + 1),
			},
		},
	}

	batches := buildBatches(cfg)
	if len(batches) < 2 {
		t.Fatalf("expected at least 2 batches, got %d", len(batches))
	}

	for i, b := range batches {
		if len(b.Peers) != 1 {
			t.Fatalf("batch %d: expected 1 peer, got %d", i, len(b.Peers))
		}
		if !b.Peers[0].AdvancedSecurity {
			t.Errorf("batch %d: AdvancedSecurity should be true", i)
		}
	}
}

func keyBytes(s string) []byte {
	k := wgtest.MustHexKey(s)
	return k[:]
}

func generateIPs(n int) []net.IPNet {
	cur, err := ipaddr.Parse("2001:db8::/64")
	if err != nil {
		panicf("failed to create cursor: %v", err)
	}

	ips := make([]net.IPNet, 0, n)
	for i := 0; i < n; i++ {
		pos := cur.Next()
		if pos == nil {
			panic("hit nil IP during IP generation")
		}

		ips = append(ips, net.IPNet{
			IP:   pos.IP,
			Mask: net.CIDRMask(128, 128),
		})
	}

	return ips
}
