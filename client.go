package wgctrl

import (
	"context"
	"errors"
	"os"

	"github.com/advanced-wg/awgctrl-go/internal/wginternal"
	"github.com/advanced-wg/awgctrl-go/wgtypes"
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
//
// The AmneziaWG fields are checked with cfg.Validate first: the netlink
// encoding is 16-bit, so e.g. Jc 70000 would otherwise reach the kernel as
// 4464 without an error. When cfg sets only some of Jc/Jmin/Jmax or of
// H1-H4, the kernel checks them together with the device's current values
// (Jmin <= Jmax, no overlapping headers); the device is then read once so
// that such a conflict is reported clearly instead of as EINVAL.
func (c *Client) ConfigureDevice(ctx context.Context, name string, cfg wgtypes.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if partialAWG(cfg) {
		// A device that cannot be read is left to the backend, which
		// reports it the usual way.
		if d, err := c.Device(ctx, name); err == nil && d.IsAmnezia {
			merged := mergeAWG(d, cfg)
			if err := merged.Validate(); err != nil {
				return err
			}
		}
	}

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

// partialAWG reports whether cfg sets some, but not all, of a group of
// AmneziaWG fields the kernel validates together: Jc/Jmin/Jmax or H1-H4.
func partialAWG(cfg wgtypes.Config) bool {
	partial := func(set ...bool) bool {
		n := 0
		for _, s := range set {
			if s {
				n++
			}
		}
		return n > 0 && n < len(set)
	}
	return partial(cfg.Jc != nil, cfg.Jmin != nil, cfg.Jmax != nil) ||
		partial(cfg.H1 != nil, cfg.H2 != nil, cfg.H3 != nil, cfg.H4 != nil)
}

// mergeAWG returns the Jc/Jmin/Jmax and H1-H4 the device would have after
// cfg is applied: the fields cfg sets, the device's current ones otherwise.
func mergeAWG(d *wgtypes.Device, cfg wgtypes.Config) wgtypes.Config {
	intOr := func(v *int, cur int) *int {
		if v != nil {
			return v
		}
		return &cur
	}
	strOr := func(v *string, cur string) *string {
		if v != nil || cur == "" {
			return v
		}
		return &cur
	}
	return wgtypes.Config{
		Jc:   intOr(cfg.Jc, d.Jc),
		Jmin: intOr(cfg.Jmin, d.Jmin),
		Jmax: intOr(cfg.Jmax, d.Jmax),
		H1:   strOr(cfg.H1, d.H1),
		H2:   strOr(cfg.H2, d.H2),
		H3:   strOr(cfg.H3, d.H3),
		H4:   strOr(cfg.H4, d.H4),
	}
}
