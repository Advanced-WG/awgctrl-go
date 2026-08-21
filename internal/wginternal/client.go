package wginternal

import (
	"context"
	"errors"
	"io"

	"github.com/awg-go/awgctrl-go/wgtypes"
)

// ErrReadOnly indicates that the driver backing a device is read-only. It is
// a sentinel value used in integration tests.
// TODO(mdlayher): consider exposing in API.
var ErrReadOnly = errors.New("driver is read-only")

// A Client is a type which can control a WireGuard device.
type Client interface {
	io.Closer
	Devices(ctx context.Context) ([]*wgtypes.Device, error)
	Device(ctx context.Context, name string) (*wgtypes.Device, error)
	ConfigureDevice(ctx context.Context, name string, cfg wgtypes.Config) error
}
