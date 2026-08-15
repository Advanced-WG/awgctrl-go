package wguser

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/advanced-wg/awgctrl-go/internal/wgtest"
	"github.com/advanced-wg/awgctrl-go/wgtypes"
)

// Example string source (with some slight modifications to use all fields):
// https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation.
const okSet = `set=1
private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
listen_port=12912
fwmark=0
replace_peers=true
public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
endpoint=[abcd:23::33%2]:51820
replace_allowed_ips=true
allowed_ip=192.168.4.4/32
public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376
update_only=true
endpoint=182.122.22.19:3233
persistent_keepalive_interval=111
replace_allowed_ips=true
allowed_ip=192.168.4.6/32
public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58
endpoint=5.152.198.39:51820
replace_allowed_ips=true
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
public_key=e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c
remove=true

`

const okAWGSet = `set=1
jc=4
jmin=80
jmax=160
s1=20
s2=35
s3=45
s4=10
h1=150000000-200000000
h2=250000000-300000000
h3=350000000-400000000
h4=450000000-500000000
i1=<r 20>
i2=<r 15>
i3=<r 12>
i4=<r 18>
i5=<r 14>
header_protection_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
content_padding_addition=5
rekey_after_time=10
rekey_timeout=15
reject_after_time=20
keepalive_timeout=25
max_handshake_attempts=30
random_trailers=true
disable_cookies=true

`

func TestClientConfigureDeviceError(t *testing.T) {
	tests := []struct {
		name     string
		device   string
		cfg      wgtypes.Config
		res      []byte
		notExist bool
	}{
		{
			name:     "not found",
			device:   "wg1",
			notExist: true,
		},
		{
			name:   "bad errno",
			device: testDevice,
			res:    []byte("errno=1\n\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, tt.res)
			defer done()

			err := c.ConfigureDevice(context.Background(), tt.device, tt.cfg)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			if !tt.notExist && errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected other error, but got not exist: %v", err)
			}
			if tt.notExist && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected not exist error, but got: %v", err)
			}
		})
	}
}

func TestClientConfigureDeviceOK(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	boolPtr := func(b bool) *bool { return &b }
	tests := []struct {
		name string
		cfg  wgtypes.Config
		req  string
	}{
		{
			name: "ok, none",
			req:  "set=1\n\n",
		},
		{
			name: "ok, clear key",
			cfg: wgtypes.Config{
				PrivateKey: &wgtypes.Key{},
			},
			req: "set=1\nprivate_key=0000000000000000000000000000000000000000000000000000000000000000\n\n",
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
			req: okSet,
		},
		{
			name: "ok, awg",
			cfg: wgtypes.Config{
				Jc:   intPtr(4),
				Jmin: intPtr(80),
				Jmax: intPtr(160),
				S1:   intPtr(20),
				S2:   intPtr(35),
				S3:   intPtr(45),
				S4:   intPtr(10),
				H1:   strPtr("150000000-200000000"),
				H2:   strPtr("250000000-300000000"),
				H3:   strPtr("350000000-400000000"),
				H4:   strPtr("450000000-500000000"),
				I1:   strPtr("<r 20>"),
				I2:   strPtr("<r 15>"),
				I3:   strPtr("<r 12>"),
				I4:   strPtr("<r 18>"),
				I5:   strPtr("<r 14>"),
				HeaderProtectionKey:    keyPtr(wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
				ContentPaddingAddition: intPtr(5),
				RekeyAfterTime:         intPtr(10),
				RekeyTimeout:           intPtr(15),
				RejectAfterTime:        intPtr(20),
				KeepaliveTimeout:       intPtr(25),
				MaxHandshakeAttempts:   intPtr(30),
				RandomTrailers:         boolPtr(true),
				DisableCookies:         boolPtr(true),
			},
			req: okAWGSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, nil)

			if err := c.ConfigureDevice(context.Background(), testDevice, tt.cfg); err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}

			req := done()

			if want, got := tt.req, string(req); want != got {
				t.Fatalf("unexpected configure request:\nwant:\n%s\ngot:\n%s", want, got)
			}
		})
	}
}
