package wgctrl

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/advanced-wg/awgctrl-go/internal/wginternal"
	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/google/go-cmp/cmp"
)

var (
	ctx = context.Background()

	errFoo = errors.New("some error")

	okDevice = &wgtypes.Device{Name: "wg0"}

	cmpErrors = cmp.Comparer(func(x, y error) bool {
		return x.Error() == y.Error()
	})
)

func TestClientClose(t *testing.T) {
	var calls int
	fn := func() error {
		calls++
		return nil
	}

	c := &Client{
		cs: []wginternal.Client{
			&testClient{CloseFunc: fn},
			&testClient{CloseFunc: fn},
		},
	}

	if err := c.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	if diff := cmp.Diff(2, calls); diff != "" {
		t.Fatalf("unexpected number of clients closed (-want +got):\n%s", diff)
	}
}

func TestClientDevices(t *testing.T) {
	fn := func(_ context.Context) ([]*wgtypes.Device, error) {
		return []*wgtypes.Device{okDevice}, nil
	}

	fn2 := func(_ context.Context) ([]*wgtypes.Device, error) {
		return []*wgtypes.Device{{Name: "wg1"}}, nil
	}

	c := &Client{
		cs: []wginternal.Client{
			&testClient{DevicesFunc: fn},
			// Same device from a second client should be deduplicated.
			&testClient{DevicesFunc: fn},
			// A different device should still appear.
			&testClient{DevicesFunc: fn2},
		},
	}

	devices, err := c.Devices(ctx)
	if err != nil {
		t.Fatalf("failed to get devices: %v", err)
	}

	if diff := cmp.Diff(2, len(devices)); diff != "" {
		t.Fatalf("unexpected number of devices (-want +got):\n%s", diff)
	}
	if devices[0].Name != "wg0" || devices[1].Name != "wg1" {
		t.Fatalf("unexpected device names: %s, %s", devices[0].Name, devices[1].Name)
	}
}

func TestClientDevice(t *testing.T) {
	type deviceFunc func(ctx context.Context, name string) (*wgtypes.Device, error)

	var (
		notExist = func(_ context.Context, _ string) (*wgtypes.Device, error) {
			return nil, os.ErrNotExist
		}

		willPanic = func(_ context.Context, _ string) (*wgtypes.Device, error) {
			panic("shouldn't be called")
		}

		returnDevice = func(_ context.Context, _ string) (*wgtypes.Device, error) {
			return okDevice, nil
		}
	)

	tests := []struct {
		name string
		fns  []deviceFunc
		err  error
	}{
		{
			name: "first error",
			fns: []deviceFunc{
				func(_ context.Context, _ string) (*wgtypes.Device, error) {
					return nil, errFoo
				},
				willPanic,
			},
			err: errFoo,
		},
		{
			name: "not found",
			fns: []deviceFunc{
				notExist,
				notExist,
			},
			err: os.ErrNotExist,
		},
		{
			name: "first not found",
			fns: []deviceFunc{
				notExist,
				returnDevice,
			},
		},
		{
			name: "first ok",
			fns: []deviceFunc{
				returnDevice,
				willPanic,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cs []wginternal.Client
			for _, fn := range tt.fns {
				cs = append(cs, &testClient{
					DeviceFunc: fn,
				})
			}

			c := &Client{cs: cs}

			d, err := c.Device(ctx, "")

			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(okDevice, d); diff != "" {
				t.Fatalf("unexpected device (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClientConfigureDevice(t *testing.T) {
	type configFunc func(ctx context.Context, name string, cfg wgtypes.Config) error

	var (
		notExist = func(_ context.Context, _ string, _ wgtypes.Config) error {
			return os.ErrNotExist
		}

		willPanic = func(_ context.Context, _ string, _ wgtypes.Config) error {
			panic("shouldn't be called")
		}

		ok = func(_ context.Context, _ string, _ wgtypes.Config) error {
			return nil
		}
	)

	tests := []struct {
		name string
		fns  []configFunc
		err  error
	}{
		{
			name: "first error",
			fns: []configFunc{
				func(_ context.Context, _ string, _ wgtypes.Config) error {
					return errFoo
				},
				willPanic,
			},
			err: errFoo,
		},
		{
			name: "not found",
			fns: []configFunc{
				notExist,
				notExist,
			},
			err: os.ErrNotExist,
		},
		{
			name: "first not found",
			fns: []configFunc{
				notExist,
				ok,
			},
		},
		{
			name: "first ok",
			fns: []configFunc{
				ok,
				willPanic,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cs []wginternal.Client
			for _, fn := range tt.fns {
				cs = append(cs, &testClient{
					ConfigureDeviceFunc: fn,
				})
			}

			c := &Client{cs: cs}

			err := c.ConfigureDevice(ctx, "", wgtypes.Config{})
			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}

type testClient struct {
	CloseFunc           func() error
	DevicesFunc         func(ctx context.Context) ([]*wgtypes.Device, error)
	DeviceFunc          func(ctx context.Context, name string) (*wgtypes.Device, error)
	ConfigureDeviceFunc func(ctx context.Context, name string, cfg wgtypes.Config) error
}

func (c *testClient) Close() error { return c.CloseFunc() }
func (c *testClient) Devices(ctx context.Context) ([]*wgtypes.Device, error) {
	return c.DevicesFunc(ctx)
}
func (c *testClient) Device(ctx context.Context, name string) (*wgtypes.Device, error) {
	return c.DeviceFunc(ctx, name)
}

func (c *testClient) ConfigureDevice(ctx context.Context, name string, cfg wgtypes.Config) error {
	return c.ConfigureDeviceFunc(ctx, name, cfg)
}

// Out-of-range AmneziaWG values are refused before any backend is asked:
// netlink would send Jc 70000 as 4464.
func TestClientConfigureDeviceValidates(t *testing.T) {
	called := false
	c := &Client{cs: []wginternal.Client{&testClient{
		ConfigureDeviceFunc: func(_ context.Context, _ string, _ wgtypes.Config) error {
			called = true
			return nil
		},
	}}}

	jc := 70000
	if err := c.ConfigureDevice(ctx, "awg0", wgtypes.Config{Jc: &jc}); err == nil {
		t.Fatal("Jc 70000 accepted")
	}
	if called {
		t.Fatal("backend called with an invalid configuration")
	}
}

// A partial Jc/Jmin/Jmax or H1-H4 update is checked together with the
// device's current values, as the kernel does, so the conflict gets a clear
// error instead of EINVAL.
func TestClientConfigureDeviceValidatesAgainstDevice(t *testing.T) {
	dev := &wgtypes.Device{
		Name: "awg0", IsAmnezia: true,
		Jc: 4, Jmin: 40, Jmax: 100,
		H1: "100-199", H2: "200-300", H3: "400", H4: "500",
	}
	intp := func(v int) *int { return &v }
	strp := func(v string) *string { return &v }

	tests := []struct {
		name    string
		cfg     wgtypes.Config
		dev     *wgtypes.Device
		devErr  error
		reads   int
		wantErr string
	}{
		{name: "Jmin above current Jmax", cfg: wgtypes.Config{Jmin: intp(500)}, dev: dev, reads: 1, wantErr: "Jmin (500) must be <= Jmax (100)"},
		{name: "Jmax below current Jmin", cfg: wgtypes.Config{Jmax: intp(20)}, dev: dev, reads: 1, wantErr: "Jmin (40) must be <= Jmax (20)"},
		{name: "Jmin within current Jmax", cfg: wgtypes.Config{Jmin: intp(90)}, dev: dev, reads: 1},
		{name: "H1 overlaps current H2", cfg: wgtypes.Config{H1: strp("250-260")}, dev: dev, reads: 1, wantErr: "H1 (250-260) and H2 (200-300) overlap"},
		{name: "H1 free of current headers", cfg: wgtypes.Config{H1: strp("600-700")}, dev: dev, reads: 1},
		{name: "full sets are not read", cfg: wgtypes.Config{
			Jc: intp(4), Jmin: intp(40), Jmax: intp(100),
			H1: strp("1"), H2: strp("2"), H3: strp("3"), H4: strp("4"),
		}, dev: dev},
		{name: "no AWG fields are not read", cfg: wgtypes.Config{ListenPort: intp(51820)}, dev: dev},
		{name: "plain WireGuard device", cfg: wgtypes.Config{Jmin: intp(500)}, dev: &wgtypes.Device{Name: "wg0"}, reads: 1},
		{name: "unreadable device is left to the backend", cfg: wgtypes.Config{Jmin: intp(500)}, devErr: errFoo, reads: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reads, configured := 0, false
			c := &Client{cs: []wginternal.Client{&testClient{
				DeviceFunc: func(_ context.Context, _ string) (*wgtypes.Device, error) {
					reads++
					return tt.dev, tt.devErr
				},
				ConfigureDeviceFunc: func(_ context.Context, _ string, _ wgtypes.Config) error {
					configured = true
					return nil
				},
			}}}

			err := c.ConfigureDevice(ctx, "awg0", tt.cfg)
			if reads != tt.reads {
				t.Fatalf("device read %d times, want %d", reads, tt.reads)
			}
			if tt.wantErr == "" {
				if err != nil || !configured {
					t.Fatalf("ConfigureDevice = %v, configured %v; want applied", err, configured)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ConfigureDevice = %v, want error containing %q", err, tt.wantErr)
			}
			if configured {
				t.Fatal("backend called with a conflicting configuration")
			}
		})
	}
}
