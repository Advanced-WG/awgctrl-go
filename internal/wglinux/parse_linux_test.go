//go:build linux
// +build linux

package wglinux

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/awg-go/awgctrl-go/internal/wgtest"
	"github.com/awg-go/awgctrl-go/wgtypes"
	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

func TestLinuxClientDevicesError(t *testing.T) {
	tests := []struct {
		name string
		msgs []genetlink.Message
	}{
		{
			name: "bad peer endpoint",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_ENDPOINT,
							Data: []byte{0xff},
						}),
					}),
				}),
			}},
		},
		{
			name: "bad peer last handshake time",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_LAST_HANDSHAKE_TIME,
							Data: []byte{0xff},
						}),
					}),
				}),
			}},
		},
		{
			name: "bad peer allowed IPs IP",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_ALLOWEDIPS,
							Data: m(netlink.Attribute{
								Type: 0,
								Data: m(netlink.Attribute{
									Type: unix.WGALLOWEDIP_A_IPADDR,
									Data: []byte{0xff},
								}),
							}),
						}),
					}),
				}),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				return tt.msgs, nil
			})
			defer c.Close()

			c.interfaces = func() ([]string, error) {
				return []string{okName}, nil
			}

			if _, err := c.Devices(context.Background()); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestLinuxClientDevicesOK(t *testing.T) {
	const (
		testIndex = 2
		testName  = "wg1"
	)

	var (
		testKey wgtypes.Key
		keyA    = wgtest.MustPublicKey()
		keyB    = wgtest.MustPublicKey()
		keyC    = wgtest.MustPublicKey()
	)

	testKey[0] = 0xff

	tests := []struct {
		name       string
		interfaces func() ([]string, error)
		msgs       [][]genetlink.Message
		devices    []*wgtypes.Device
	}{
		{
			name: "basic",
			interfaces: func() ([]string, error) {
				return []string{okName, "wg1"}, nil
			},
			msgs: [][]genetlink.Message{
				{{
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFINDEX,
							Data: nlenc.Uint32Bytes(okIndex),
						},
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(okName),
						},
					}...),
				}},
				{{
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFINDEX,
							Data: nlenc.Uint32Bytes(testIndex),
						},
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(testName),
						},
					}...),
				}},
			},
			devices: []*wgtypes.Device{
				{
					Name: okName,
					Type: wgtypes.LinuxKernel,
				},
				{
					Name: "wg1",
					Type: wgtypes.LinuxKernel,
				},
			},
		},
		{
			name: "complete",
			msgs: [][]genetlink.Message{{{
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGDEVICE_A_IFINDEX,
						Data: nlenc.Uint32Bytes(okIndex),
					},
					{
						Type: unix.WGDEVICE_A_IFNAME,
						Data: nlenc.Bytes(okName),
					},
					{
						Type: unix.WGDEVICE_A_PRIVATE_KEY,
						Data: testKey[:],
					},
					{
						Type: unix.WGDEVICE_A_PUBLIC_KEY,
						Data: testKey[:],
					},
					{
						Type: unix.WGDEVICE_A_LISTEN_PORT,
						Data: nlenc.Uint16Bytes(5555),
					},
					{
						Type: unix.WGDEVICE_A_FWMARK,
						Data: nlenc.Uint32Bytes(0xff),
					},
					{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_PRESHARED_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_ENDPOINT,
										Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
											Addr: [4]byte{192, 168, 1, 1},
											Port: sockaddrPort(1111),
										})))[:],
									},
									{
										Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
										Data: nlenc.Uint16Bytes(10),
									},
									{
										Type: unix.WGPEER_A_LAST_HANDSHAKE_TIME,
										Data: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
											Sec:  10,
											Nsec: 20,
										})))[:],
									},
									{
										Type: unix.WGPEER_A_RX_BYTES,
										Data: nlenc.Uint64Bytes(100),
									},
									{
										Type: unix.WGPEER_A_TX_BYTES,
										Data: nlenc.Uint64Bytes(200),
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("192.168.1.10/32"),
											wgtest.MustCIDR("fd00::1/128"),
										}),
									},
									{
										Type: unix.WGPEER_A_PROTOCOL_VERSION,
										Data: nlenc.Uint32Bytes(1),
									},
								}...),
							},
							// "dummy" peer with only some necessary fields.
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_ENDPOINT,
										Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
											Addr: [16]byte{
												0xfe, 0x80, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x01,
											},
											Port: sockaddrPort(2222),
										})))[:],
									},
								}...),
							},
						}...),
					},
				}...),
			}}},
			devices: []*wgtypes.Device{
				{
					Name:         okName,
					Type:         wgtypes.LinuxKernel,
					PrivateKey:   testKey,
					PublicKey:    testKey,
					ListenPort:   5555,
					FirewallMark: 0xff,
					Peers: []wgtypes.Peer{
						{
							PublicKey:    testKey,
							PresharedKey: testKey,
							Endpoint: &net.UDPAddr{
								IP:   net.IPv4(192, 168, 1, 1),
								Port: 1111,
							},
							PersistentKeepaliveInterval: 10 * time.Second,
							LastHandshakeTime:           time.Unix(10, 20),
							ReceiveBytes:                100,
							TransmitBytes:               200,
							AllowedIPs: []net.IPNet{
								wgtest.MustCIDR("192.168.1.10/32"),
								wgtest.MustCIDR("fd00::1/128"),
							},
							ProtocolVersion: 1,
						},
						{
							PublicKey: testKey,
							Endpoint: &net.UDPAddr{
								IP:   net.ParseIP("fe80::1"),
								Port: 2222,
							},
						},
					},
				},
			},
		},
		{
			name: "merge devices",
			msgs: [][]genetlink.Message{{
				// The "target" device.
				{
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(okName),
						},
						{
							Type: unix.WGDEVICE_A_PRIVATE_KEY,
							Data: testKey[:],
						},
						{
							Type: unix.WGDEVICE_A_PEERS,
							Data: m(netlink.Attribute{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyA[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("192.168.1.10/32"),
											wgtest.MustCIDR("192.168.1.11/32"),
										}),
									},
								}...),
							}),
						},
					}...),
				},
				// Continuation of first peer list, new peer list.
				{
					Data: m(netlink.Attribute{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyA[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("fd00:dead:beef:dead::/64"),
											wgtest.MustCIDR("fd00:dead:beef:ffff::/64"),
										}),
									},
								}...),
							},
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyB[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("10.10.10.0/24"),
											wgtest.MustCIDR("10.10.11.0/24"),
										}),
									},
								}...),
							},
						}...),
					}),
				},
				// Continuation of previous peer list, new peer list.
				{
					Data: m(netlink.Attribute{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyB[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("10.10.12.0/24"),
											wgtest.MustCIDR("10.10.13.0/24"),
										}),
									},
								}...),
							},
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyC[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("fd00:1234::/32"),
											wgtest.MustCIDR("fd00:4567::/32"),
										}),
									},
								}...),
							},
						}...),
					}),
				},
			}},
			devices: []*wgtypes.Device{
				{
					Name:       okName,
					Type:       wgtypes.LinuxKernel,
					PrivateKey: testKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey: keyA,
							AllowedIPs: []net.IPNet{
								wgtest.MustCIDR("192.168.1.10/32"),
								wgtest.MustCIDR("192.168.1.11/32"),
								wgtest.MustCIDR("fd00:dead:beef:dead::/64"),
								wgtest.MustCIDR("fd00:dead:beef:ffff::/64"),
							},
						},
						{
							PublicKey: keyB,
							AllowedIPs: []net.IPNet{
								wgtest.MustCIDR("10.10.10.0/24"),
								wgtest.MustCIDR("10.10.11.0/24"),
								wgtest.MustCIDR("10.10.12.0/24"),
								wgtest.MustCIDR("10.10.13.0/24"),
							},
						},
						{
							PublicKey: keyC,
							AllowedIPs: []net.IPNet{
								wgtest.MustCIDR("fd00:1234::/32"),
								wgtest.MustCIDR("fd00:4567::/32"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				cmd   = unix.WG_CMD_GET_DEVICE
				flags = netlink.Request | netlink.Dump
			)

			// Advance through the test messages on subsequent calls.
			var i int
			fn := func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				defer func() { i++ }()

				return tt.msgs[i], nil
			}

			c := testClient(t, genltest.CheckRequest(familyID, cmd, flags, fn))
			defer c.Close()

			// Replace interfaces if necessary.
			if tt.interfaces != nil {
				c.interfaces = tt.interfaces
			}

			devices, err := c.Devices(context.Background())
			if err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}

			if diff := cmp.Diff(tt.devices, devices); diff != "" {
				t.Fatalf("unexpected devices (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_parseTimespec(t *testing.T) {
	var zero [sizeofTimespec64]byte

	tests := []struct {
		name string
		b    []byte
		t    time.Time
		ok   bool
	}{
		{
			name: "bad",
			b:    []byte{0xff},
		},
		{
			name: "timespec32",
			b: (*(*[sizeofTimespec32]byte)(unsafe.Pointer(&timespec32{
				Sec:  1,
				Nsec: 2,
			})))[:],
			t:  time.Unix(1, 2),
			ok: true,
		},
		{
			name: "timespec64",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Sec:  2,
				Nsec: 1,
			})))[:],
			t:  time.Unix(2, 1),
			ok: true,
		},
		{
			name: "zero seconds",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Nsec: 1,
			})))[:],
			t:  time.Unix(0, 1),
			ok: true,
		},
		{
			name: "zero nanoseconds",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Sec: 1,
			})))[:],
			t:  time.Unix(1, 0),
			ok: true,
		},
		{
			name: "zero both",
			b:    zero[:],
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got time.Time
			err := parseTimespec(&got)(tt.b)
			if tt.ok && err != nil {
				t.Fatalf("failed to parse timespec: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			if diff := cmp.Diff(tt.t, got); diff != "" {
				t.Fatalf("unexpected time (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_timespec32MemoryLayout(t *testing.T) {
	// Assume unix.Timespec has 32-bit integers exclusively.
	if a := runtime.GOARCH; a != "386" {
		t.Skipf("skipping, architecture %q not handled in 32-bit only test", a)
	}

	// Verify unix.Timespec and timespec32 have an identical memory layout.
	uts := unix.Timespec{
		Sec:  1,
		Nsec: 2,
	}

	if diff := cmp.Diff(sizeofTimespec32, int(unsafe.Sizeof(unix.Timespec{}))); diff != "" {
		t.Fatalf("unexpected timespec size (-want +got):\n%s", diff)
	}

	ts := *(*timespec32)(unsafe.Pointer(&uts))

	if diff := cmp.Diff(uts.Sec, ts.Sec); diff != "" {
		t.Fatalf("unexpected timespec seconds (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(uts.Nsec, ts.Nsec); diff != "" {
		t.Fatalf("unexpected timespec nanoseconds (-want +got):\n%s", diff)
	}
}

func Test_timespec64MemoryLayout(t *testing.T) {
	// Assume unix.Timespec has 64-bit integers exclusively.
	if a := runtime.GOARCH; a != "amd64" {
		t.Skipf("skipping, architecture %q not handled in 64-bit only test", a)
	}

	// Verify unix.Timespec and timespec64 have an identical memory layout.
	uts := unix.Timespec{
		Sec:  1,
		Nsec: 2,
	}

	if diff := cmp.Diff(sizeofTimespec64, int(unsafe.Sizeof(unix.Timespec{}))); diff != "" {
		t.Fatalf("unexpected timespec size (-want +got):\n%s", diff)
	}

	ts := *(*timespec64)(unsafe.Pointer(&uts))

	if diff := cmp.Diff(uts.Sec, ts.Sec); diff != "" {
		t.Fatalf("unexpected timespec seconds (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(uts.Nsec, ts.Nsec); diff != "" {
		t.Fatalf("unexpected timespec nanoseconds (-want +got):\n%s", diff)
	}
}

// TestParseDeviceAWGAttributes verifies that AmneziaWG-specific netlink
// attributes are correctly parsed into the Device struct.
func TestParseDeviceAWGAttributes(t *testing.T) {
	// Build a minimal netlink message with AWG attributes.
	// We encode the attributes the same way the kernel would send them.
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, "awg0")
	ae.Uint16(WGDEVICE_A_JC, 5)
	ae.Uint16(WGDEVICE_A_JMIN, 100)
	ae.Uint16(WGDEVICE_A_JMAX, 200)
	ae.Uint16(WGDEVICE_A_S1, 30)
	ae.Uint16(WGDEVICE_A_S2, 40)
	ae.Uint16(WGDEVICE_A_S3, 50)
	ae.Uint16(WGDEVICE_A_S4, 8)
	ae.Uint64(WGDEVICE_A_H1, uint64(223456789)<<32|123456789)
	ae.Uint64(WGDEVICE_A_H2, uint64(400000000)<<32|300000000)
	ae.Uint64(WGDEVICE_A_H3, uint64(600000000)<<32|500000000)
	ae.Uint64(WGDEVICE_A_H4, uint64(800000000)<<32|700000000)
	ae.String(WGDEVICE_A_I1, "<r 20>")
	ae.String(WGDEVICE_A_I2, "<r 15>")
	ae.String(WGDEVICE_A_I3, "<r 12>")
	ae.String(WGDEVICE_A_I4, "<r 18>")
	ae.String(WGDEVICE_A_I5, "<r 14>")
	ae.Bytes(WGDEVICE_A_HEADER_PROTECTION_KEY, keyBytes("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"))
	ae.Uint32(WGDEVICE_A_CONTENT_PADDING_ADDITION, wgtypes.UintRange{Min: 10, Max: 100}.PackU16())
	ae.Uint32(WGDEVICE_A_REKEY_AFTER_TIME, wgtypes.UintRange{Min: 10, Max: 10}.PackU16())
	ae.Uint32(WGDEVICE_A_REKEY_TIMEOUT, wgtypes.UintRange{Min: 15, Max: 15}.PackU16())
	ae.Uint32(WGDEVICE_A_REJECT_AFTER_TIME, wgtypes.UintRange{Min: 20, Max: 20}.PackU16())
	ae.Uint32(WGDEVICE_A_KEEPALIVE_TIMEOUT, wgtypes.UintRange{Min: 25, Max: 25}.PackU16())
	ae.Uint32(WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, wgtypes.UintRange{Min: 30, Max: 30}.PackU16())
	ae.Uint8(WGDEVICE_A_RANDOM_TRAILERS, 1)
	ae.Uint8(WGDEVICE_A_DISABLE_COOKIES, 1)

	b, err := ae.Encode()
	if err != nil {
		t.Fatalf("failed to encode attributes: %v", err)
	}

	msg := genetlink.Message{Data: b}
	d, err := parseDeviceLoop(msg, 3)
	if err != nil {
		t.Fatalf("parseDeviceLoop: %v", err)
	}

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Name", d.Name, "awg0"},
		{"Jc", d.Jc, 5},
		{"Jmin", d.Jmin, 100},
		{"Jmax", d.Jmax, 200},
		{"S1", d.S1, 30},
		{"S2", d.S2, 40},
		{"S3", d.S3, 50},
		{"S4", d.S4, 8},
		{"H1", d.H1, "123456789-223456789"},
		{"H2", d.H2, "300000000-400000000"},
		{"H3", d.H3, "500000000-600000000"},
		{"H4", d.H4, "700000000-800000000"},
		{"I1", d.I1, "<r 20>"},
		{"I2", d.I2, "<r 15>"},
		{"I3", d.I3, "<r 12>"},
		{"I4", d.I4, "<r 18>"},
		{"I5", d.I5, "<r 14>"},
		{"HeaderProtectionKey", d.HeaderProtectionKey, wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")},
		{"ContentPaddingAddition", d.ContentPaddingAddition, wgtypes.UintRange{Min: 10, Max: 100}},
		{"RekeyAfterTime", d.RekeyAfterTime, wgtypes.UintRange{Min: 10, Max: 10}},
		{"RekeyTimeout", d.RekeyTimeout, wgtypes.UintRange{Min: 15, Max: 15}},
		{"RejectAfterTime", d.RejectAfterTime, wgtypes.UintRange{Min: 20, Max: 20}},
		{"KeepaliveTimeout", d.KeepaliveTimeout, wgtypes.UintRange{Min: 25, Max: 25}},
		{"MaxHandshakeAttempts", d.MaxHandshakeAttempts, wgtypes.UintRange{Min: 30, Max: 30}},
		{"RandomTrailers", d.RandomTrailers, true},
		{"DisableCookies", d.DisableCookies, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestParseDeviceAWGAttributesV2(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.String(WGDEVICE_A_H1, "123456789-223456789")
	b, _ := ae.Encode()

	d, err := parseDeviceLoop(genetlink.Message{Data: b}, 2)
	if err != nil {
		t.Fatalf("parseDeviceLoop: %v", err)
	}
	if d.H1 != "123456789-223456789" {
		t.Errorf("got %q, want %q", d.H1, "123456789-223456789")
	}
}

func TestParseDeviceAWGAttributesV1(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(WGDEVICE_A_H1, 123456789)
	b, _ := ae.Encode()

	d, err := parseDeviceLoop(genetlink.Message{Data: b}, 1)
	if err != nil {
		t.Fatalf("parseDeviceLoop: %v", err)
	}
	if d.H1 != "123456789" {
		t.Errorf("got %q, want %q", d.H1, "123456789")
	}
}

func TestParsePeerPersistentKeepalive(t *testing.T) {
	var testKey wgtypes.Key
	testKey[0] = 0xab

	tests := []struct {
		name string
		data []byte
		want time.Duration
	}{
		{
			name: "uint16 wireguard/awg1/awg2",
			data: nlenc.Uint16Bytes(25),
			want: 25 * time.Second,
		},
		{
			name: "uint32 packed u16_range awg3",
			// hi<<16 | lo, both 25: a naive Uint32()*Second would be ~19 days.
			data: nlenc.Uint32Bytes(uint32(25)<<16 | 25),
			want: 25 * time.Second,
		},
		{
			name: "uint32 packed range uses lo",
			data: nlenc.Uint32Bytes(uint32(40)<<16 | 10),
			want: 10 * time.Second,
		},
		{
			name: "zero",
			data: nlenc.Uint16Bytes(0),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := genetlink.Message{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m([]netlink.Attribute{
							{Type: unix.WGPEER_A_PUBLIC_KEY, Data: testKey[:]},
							{Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, Data: tt.data},
						}...),
					}),
				}),
			}

			d, err := parseDeviceLoop(msg, 3)
			if err != nil {
				t.Fatalf("parseDeviceLoop: %v", err)
			}
			if len(d.Peers) != 1 {
				t.Fatalf("expected 1 peer, got %d", len(d.Peers))
			}
			if d.Peers[0].PersistentKeepaliveInterval != tt.want {
				t.Errorf("got %v, want %v", d.Peers[0].PersistentKeepaliveInterval, tt.want)
			}
		})
	}
}

// TestParsePeerAdvancedSecurity verifies that the WGPEER_A_ADVANCED_SECURITY
// NLA_FLAG attribute is correctly parsed as a boolean on the Peer struct.
func TestParsePeerAdvancedSecurity(t *testing.T) {
	var testKey wgtypes.Key
	testKey[0] = 0xab

	tests := []struct {
		name     string
		peerData []byte
		want     bool
	}{
		{
			name: "advanced security present",
			peerData: m([]netlink.Attribute{
				{
					Type: unix.WGPEER_A_PUBLIC_KEY,
					Data: testKey[:],
				},
				{
					// NLA_FLAG: zero-length attribute; presence means true.
					Type: uint16(WGPEER_A_ADVANCED_SECURITY),
					Data: []byte{},
				},
			}...),
			want: true,
		},
		{
			name: "advanced security absent",
			peerData: m([]netlink.Attribute{
				{
					Type: unix.WGPEER_A_PUBLIC_KEY,
					Data: testKey[:],
				},
			}...),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := genetlink.Message{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: tt.peerData,
					}),
				}),
			}

			d, err := parseDeviceLoop(msg, 3)
			if err != nil {
				t.Fatalf("parseDeviceLoop: %v", err)
			}

			if len(d.Peers) != 1 {
				t.Fatalf("expected 1 peer, got %d", len(d.Peers))
			}

			if d.Peers[0].AdvancedSecurity != tt.want {
				t.Errorf("AdvancedSecurity = %v, want %v", d.Peers[0].AdvancedSecurity, tt.want)
			}
		})
	}
}

// TestParseDeviceAWGComplete tests end-to-end parsing of an AWG device
// with obfuscation parameters and peers that have AdvancedSecurity enabled.
func TestParseDeviceAWGComplete(t *testing.T) {
	var testKey wgtypes.Key
	testKey[0] = 0xcc

	peerKey := wgtest.MustPublicKey()

	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, "awg0")
	ae.Uint16(unix.WGDEVICE_A_LISTEN_PORT, 51820)

	// AWG device parameters.
	ae.Uint16(WGDEVICE_A_JC, 4)
	ae.Uint16(WGDEVICE_A_JMIN, 80)
	ae.Uint16(WGDEVICE_A_JMAX, 160)
	ae.Uint16(WGDEVICE_A_S1, 20)
	ae.Uint16(WGDEVICE_A_S2, 35)
	ae.Uint16(WGDEVICE_A_S3, 45)
	ae.Uint16(WGDEVICE_A_S4, 10)
	ae.Uint64(WGDEVICE_A_H1, uint64(200000000)<<32|150000000)
	ae.Uint64(WGDEVICE_A_H2, uint64(300000000)<<32|250000000)
	ae.Uint64(WGDEVICE_A_H3, uint64(400000000)<<32|350000000)
	ae.Uint64(WGDEVICE_A_H4, uint64(500000000)<<32|450000000)
	ae.String(WGDEVICE_A_I1, "<r 20>")
	ae.String(WGDEVICE_A_I2, "<r 15>")
	ae.String(WGDEVICE_A_I3, "<r 12>")
	ae.String(WGDEVICE_A_I4, "<r 18>")
	ae.String(WGDEVICE_A_I5, "<r 14>")
	ae.Bytes(WGDEVICE_A_HEADER_PROTECTION_KEY, keyBytes("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"))
	ae.Uint32(WGDEVICE_A_CONTENT_PADDING_ADDITION, wgtypes.UintRange{Min: 10, Max: 100}.PackU16())
	ae.Uint32(WGDEVICE_A_REKEY_AFTER_TIME, wgtypes.UintRange{Min: 10, Max: 10}.PackU16())
	ae.Uint32(WGDEVICE_A_REKEY_TIMEOUT, wgtypes.UintRange{Min: 15, Max: 15}.PackU16())
	ae.Uint32(WGDEVICE_A_REJECT_AFTER_TIME, wgtypes.UintRange{Min: 20, Max: 20}.PackU16())
	ae.Uint32(WGDEVICE_A_KEEPALIVE_TIMEOUT, wgtypes.UintRange{Min: 25, Max: 25}.PackU16())
	ae.Uint32(WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, wgtypes.UintRange{Min: 30, Max: 30}.PackU16())
	ae.Uint8(WGDEVICE_A_RANDOM_TRAILERS, 1)
	ae.Uint8(WGDEVICE_A_DISABLE_COOKIES, 1)

	b, err := ae.Encode()
	if err != nil {
		t.Fatalf("failed to encode device attributes: %v", err)
	}

	// Build peer with AdvancedSecurity flag and allowed IPs.
	peerAttrs := m([]netlink.Attribute{
		{
			Type: unix.WGPEER_A_PUBLIC_KEY,
			Data: peerKey[:],
		},
		{
			Type: unix.WGPEER_A_ENDPOINT,
			Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
				Addr: [4]byte{10, 0, 0, 1},
				Port: sockaddrPort(51820),
			})))[:],
		},
		{
			Type: unix.WGPEER_A_RX_BYTES,
			Data: nlenc.Uint64Bytes(1024),
		},
		{
			Type: unix.WGPEER_A_TX_BYTES,
			Data: nlenc.Uint64Bytes(2048),
		},
		{
			Type: uint16(WGPEER_A_ADVANCED_SECURITY),
			Data: []byte{},
		},
		{
			Type: unix.WGPEER_A_ALLOWEDIPS,
			Data: mustAllowedIPs([]net.IPNet{
				wgtest.MustCIDR("10.0.0.0/24"),
			}),
		},
	}...)

	peersData := m(netlink.Attribute{
		Type: 0,
		Data: peerAttrs,
	})

	// Append the peers attribute to the device data.
	fullData := append(b, m(netlink.Attribute{
		Type: unix.WGDEVICE_A_PEERS,
		Data: peersData,
	})...)

	msg := genetlink.Message{Data: fullData}
	d, err := parseDeviceLoop(msg, 3)
	if err != nil {
		t.Fatalf("parseDeviceLoop: %v", err)
	}

	want := &wgtypes.Device{
		Name:                   "awg0",
		Type:                   wgtypes.LinuxKernel,
		ListenPort:             51820,
		Jc:                     4,
		Jmin:                   80,
		Jmax:                   160,
		S1:                     20,
		S2:                     35,
		S3:                     45,
		S4:                     10,
		H1:                     "150000000-200000000",
		H2:                     "250000000-300000000",
		H3:                     "350000000-400000000",
		H4:                     "450000000-500000000",
		I1:                     "<r 20>",
		I2:                     "<r 15>",
		I3:                     "<r 12>",
		I4:                     "<r 18>",
		I5:                     "<r 14>",
		HeaderProtectionKey:    wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"),
		ContentPaddingAddition: wgtypes.UintRange{Min: 10, Max: 100},
		RekeyAfterTime:         wgtypes.UintRange{Min: 10, Max: 10},
		RekeyTimeout:           wgtypes.UintRange{Min: 15, Max: 15},
		RejectAfterTime:        wgtypes.UintRange{Min: 20, Max: 20},
		KeepaliveTimeout:       wgtypes.UintRange{Min: 25, Max: 25},
		MaxHandshakeAttempts:   wgtypes.UintRange{Min: 30, Max: 30},
		RandomTrailers:         true,
		DisableCookies:         true,
		Peers: []wgtypes.Peer{
			{
				PublicKey: peerKey,
				Endpoint: &net.UDPAddr{
					IP:   net.IPv4(10, 0, 0, 1),
					Port: 51820,
				},
				ReceiveBytes:     1024,
				TransmitBytes:    2048,
				AdvancedSecurity: true,
				AllowedIPs: []net.IPNet{
					wgtest.MustCIDR("10.0.0.0/24"),
				},
			},
		},
	}

	if diff := cmp.Diff(want, d); diff != "" {
		t.Fatalf("unexpected AWG device (-want +got):\n%s", diff)
	}
}

// TestParseDeviceAWGZeroValues verifies that AWG attributes parse correctly
// when all values are zero (AWG disabled but attributes still present).
func TestParseDeviceAWGZeroValues(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, "awg0")
	ae.Uint16(WGDEVICE_A_JC, 0)
	ae.Uint16(WGDEVICE_A_JMIN, 0)
	ae.Uint16(WGDEVICE_A_JMAX, 0)
	ae.Uint16(WGDEVICE_A_S1, 0)
	ae.Uint16(WGDEVICE_A_S2, 0)
	ae.Uint16(WGDEVICE_A_S3, 0)
	ae.Uint16(WGDEVICE_A_S4, 0)

	b, err := ae.Encode()
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	d, err := parseDeviceLoop(genetlink.Message{Data: b}, 3)
	if err != nil {
		t.Fatalf("parseDeviceLoop: %v", err)
	}

	if d.Jc != 0 || d.Jmin != 0 || d.Jmax != 0 {
		t.Errorf("expected zero junk params, got Jc=%d Jmin=%d Jmax=%d", d.Jc, d.Jmin, d.Jmax)
	}
	if d.S1 != 0 || d.S2 != 0 || d.S3 != 0 || d.S4 != 0 {
		t.Errorf("expected zero padding, got S1=%d S2=%d S3=%d S4=%d", d.S1, d.S2, d.S3, d.S4)
	}
}

func TestParseDeviceAWG3LegacySingleU32(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(WGDEVICE_A_CONTENT_PADDING_ADDITION, 5)
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseDeviceLoop(genetlink.Message{Data: b}, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := wgtypes.UintRange{Min: 5, Max: 5}
	if d.ContentPaddingAddition != want {
		t.Errorf("legacy u32 5 = %+v, want %+v", d.ContentPaddingAddition, want)
	}
}
