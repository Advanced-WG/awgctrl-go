package wgctrl

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/awg-go/awgctrl-go/internal/wginternal"
	"github.com/awg-go/awgctrl-go/wgtypes"
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
