package wgctrl

import (
	"context"
	"errors"
	"os"

	"github.com/awg-go/awgctrl-go/internal/wginternal"
	"github.com/awg-go/awgctrl-go/wgtypes"
)

// Expose an identical interface to the underlying packages.
var _ wginternal.Client = &Client{}

// A Client provides access to WireGuard device information.
type Client struct {
	// Seamlessly use different wginternal.Client implementations to provide an
	// interface similar to wg(8).
	cs []wginternal.Client
}

// New creates a new Client.
func New() (*Client, error) {
	cs, err := newClients()
	if err != nil {
		return nil, err
	}

	return &Client{
		cs: cs,
	}, nil
}

// Close releases resources used by a Client.
//
// All underlying clients are closed regardless of errors. If multiple
// clients fail to close, their errors are joined with errors.Join so
// callers can inspect individual errors via errors.Is / errors.As.
func (c *Client) Close() error {
	var errs []error
	for _, wgc := range c.cs {
		if err := wgc.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// Devices retrieves all WireGuard devices on this system.
//
// When multiple backend clients report the same device (identified by
// interface name), only the first occurrence is kept. This prevents
// duplicates when, for example, both kernel and userspace clients
// discover the same interface.
func (c *Client) Devices(ctx context.Context) ([]*wgtypes.Device, error) {
	seen := make(map[string]struct{})
	var out []*wgtypes.Device

	for _, wgc := range c.cs {
		devs, err := wgc.Devices(ctx)
		if err != nil {
			return nil, err
		}

		for _, d := range devs {
			if _, ok := seen[d.Name]; ok {
				continue
			}
			seen[d.Name] = struct{}{}
			out = append(out, d)
		}
	}

	return out, nil
}

// Device retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using `errors.Is(err, os.ErrNotExist)`.
func (c *Client) Device(ctx context.Context, name string) (*wgtypes.Device, error) {
	for _, wgc := range c.cs {
		d, err := wgc.Device(ctx, name)
		switch {
		case err == nil:
			return d, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return nil, err
		}
	}

	return nil, os.ErrNotExist
}

// ConfigureDevice configures a WireGuard device by its interface name.
//
// Because the zero value of some Go types may be significant to WireGuard for
// Config fields, only fields which are not nil will be applied when
// configuring a device.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using `errors.Is(err, os.ErrNotExist)`.
func (c *Client) ConfigureDevice(ctx context.Context, name string, cfg wgtypes.Config) error {
	for _, wgc := range c.cs {
		err := wgc.ConfigureDevice(ctx, name, cfg)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return err
		}
	}

	return os.ErrNotExist
}
