//go:build linux
// +build linux

package wglinux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/advanced-wg/awgctrl-go/internal/wginternal"
	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Constants for AmneziaWG identification
const (
	amneziaGenlName = "amneziawg"
	amneziaKind     = "amneziawg"
)

var _ wginternal.Client = &Client{}

// A Client provides access to Linux WireGuard netlink information.
type Client struct {
	c *genetlink.Conn

	// Store pointers to families so we can distinguish if they are loaded.
	// These structs contain the Name, ID, and Version required for requests.
	wgFamily      *genetlink.Family
	amneziaFamily *genetlink.Family

	interfaces func() ([]string, error)

	// linkKind returns the rtnetlink kind of a link ("wireguard",
	// "amneziawg", ...), or os.ErrNotExist.
	linkKind func(name string) (string, error)
}

// New creates a new Client and returns whether or not the generic netlink
// interface is available.
func New() (*Client, bool, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, false, err
	}

	// Best effort version of netlink.Config.Strict due to CentOS 7.
	for _, o := range []netlink.ConnOption{
		netlink.ExtendedAcknowledge,
		netlink.GetStrictCheck,
	} {
		_ = c.SetOption(o, true)
	}

	return initClient(c)
}

// initClient is the internal Client constructor used in some tests.
func initClient(c *genetlink.Conn) (*Client, bool, error) {
	// Try to locate the standard WireGuard family.
	wg, errWg := c.GetFamily(unix.WG_GENL_NAME)

	// Try to locate the AmneziaWG family.
	// Using a pointer to distinguish between "not found" and "found".
	var amnezia *genetlink.Family
	if af, err := c.GetFamily(amneziaGenlName); err == nil {
		amnezia = &af
	}

	// If neither family is found, return the error from the standard WG lookup.
	if errWg != nil && amnezia == nil {
		_ = c.Close()

		// If WG is missing but we had a specific Netlink error (not just NotExist), return it.
		if !errors.Is(errWg, os.ErrNotExist) {
			return nil, false, errWg
		}
		// If both are strictly missing (NotExist), return false with no error (not supported).
		return nil, false, nil
	}

	// Make a pointer for standard WG if it was found.
	var wgPtr *genetlink.Family
	if errWg == nil {
		wgPtr = &wg
	}

	return &Client{
		c:             c,
		wgFamily:      wgPtr,
		amneziaFamily: amnezia,
		interfaces:    rtnlInterfaces,
		linkKind:      rtnlLinkKind,
	}, true, nil
}

// Close implements wginternal.Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Devices implements wginternal.Client.
func (c *Client) Devices(ctx context.Context) ([]*wgtypes.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// By default, rtnetlink is used to fetch a list of all interfaces and then
	// filter that list to only find WireGuard/AmneziaWG interfaces.
	//
	// The remainder of this function assumes that any returned device from this
	// function is a valid WireGuard device.
	ifis, err := c.interfaces()
	if err != nil {
		return nil, err
	}

	ds := make([]*wgtypes.Device, 0, len(ifis))
	for _, ifi := range ifis {
		d, err := c.Device(ctx, ifi)
		if err != nil {
			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

// Device implements wginternal.Client.
func (c *Client) Device(ctx context.Context, name string) (*wgtypes.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if name == "" {
		return nil, os.ErrNotExist
	}

	family, err := c.familyFor(name)
	if err != nil {
		return nil, err
	}
	return c.getDeviceInternal(name, *family)
}

// ConfigureDevice implements wginternal.Client.
func (c *Client) ConfigureDevice(ctx context.Context, name string, cfg wgtypes.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	family, err := c.familyFor(name)
	if err != nil {
		return err
	}

	batches := buildBatches(cfg)
	if len(batches) == 0 {
		return nil
	}

	for _, batch := range batches {
		if err := ctx.Err(); err != nil {
			return err
		}

		attrs, err := configAttrs(name, batch)
		if err != nil {
			return err
		}

		// Proceed with the family determined in the first step.
		if _, err := c.execute(*family, unix.WG_CMD_SET_DEVICE, netlink.Request|netlink.Acknowledge, attrs); err != nil {
			return err
		}
	}

	return nil
}

// familyFor returns the generic netlink family that serves the named device,
// chosen by its link kind. This costs one small rtnetlink request; fetching
// the device instead would dump it with all its peers before every change.
func (c *Client) familyFor(name string) (*genetlink.Family, error) {
	kind, err := c.linkKind(name)
	if err != nil {
		return nil, err
	}

	switch {
	case kind == wgKind && c.wgFamily != nil:
		return c.wgFamily, nil
	case kind == amneziaKind && c.amneziaFamily != nil:
		return c.amneziaFamily, nil
	}

	// Not a kernel WireGuard/AmneziaWG link (e.g. a userspace tun device).
	return nil, os.ErrNotExist
}

// getDeviceInternal executes the netlink call to fetch device details for a specific family.
func (c *Client) getDeviceInternal(name string, family genetlink.Family) (*wgtypes.Device, error) {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(name),
	}})
	if err != nil {
		return nil, err
	}

	msgs, err := c.execute(family, unix.WG_CMD_GET_DEVICE, netlink.Request|netlink.Dump, b)
	if err != nil {
		return nil, err
	}

	d, err := parseDevice(msgs)
	if err != nil {
		return nil, err
	}

	if family.Name == amneziaGenlName {
		d.IsAmnezia = true
	}

	return d, nil
}

// execute executes a single Netlink request.
// It uses the passed family to determine the Family ID and the Generic Netlink Version.
func (c *Client) execute(family genetlink.Family, command uint8, flags netlink.HeaderFlags, attrb []byte) ([]genetlink.Message, error) {
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: family.Version, // Use the version reported by the kernel (e.g. 2 for Amnezia)
		},
		Data: attrb,
	}

	msgs, err := c.c.Execute(msg, family.ID, flags)
	if err == nil {
		return msgs, nil
	}

	oerr, ok := err.(*netlink.OpError)
	if !ok {
		return nil, fmt.Errorf("wglinux: netlink operation returned non-netlink error: %w", err)
	}

	switch oerr.Err {
	case unix.ENODEV, unix.ENOTSUP:
		return nil, os.ErrNotExist
	default:
		return nil, oerr.Err
	}
}

// rtnlInterfaces uses rtnetlink to fetch a list of WireGuard interfaces.
func rtnlInterfaces() ([]string, error) {
	// Use the stdlib's rtnetlink helpers to get ahold of a table of all
	// interfaces, so we can begin filtering it down to just WireGuard devices.
	tab, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to get list of interfaces from rtnetlink: %w", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to parse rtnetlink messages: %w", err)
	}

	return parseRTNLInterfaces(msgs)
}

// rtnlLinkKind returns the IFLA_INFO_KIND of the named link using a single
// RTM_GETLINK request for that name (no dump of all links).
func rtnlLinkKind(name string) (string, error) {
	if name == "" || len(name) >= unix.IFNAMSIZ {
		return "", os.ErrNotExist
	}

	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return "", fmt.Errorf("wglinux: failed to dial rtnetlink: %w", err)
	}
	defer conn.Close()

	ae := netlink.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, name)
	attrs, err := ae.Encode()
	if err != nil {
		return "", err
	}

	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETLINK,
			Flags: netlink.Request,
		},
		// struct ifinfomsg (all zero: any family, look up by name) + attributes
		Data: append(make([]byte, unix.SizeofIfInfomsg), attrs...),
	})
	if err != nil {
		var oerr *netlink.OpError
		if errors.As(err, &oerr) && errors.Is(oerr.Err, unix.ENODEV) {
			return "", os.ErrNotExist
		}
		return "", fmt.Errorf("wglinux: failed to look up link %q: %w", name, err)
	}

	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWLINK {
			continue
		}
		return parseLinkKind(m.Data)
	}
	return "", os.ErrNotExist
}

// parseLinkKind returns the IFLA_INFO_KIND of an RTM_NEWLINK payload
// (ifinfomsg followed by attributes); "" if the link has none.
func parseLinkKind(b []byte) (string, error) {
	if len(b) < unix.SizeofIfInfomsg {
		return "", fmt.Errorf("wglinux: rtnetlink message is too short for ifinfomsg: %d", len(b))
	}

	ad, err := netlink.NewAttributeDecoder(b[unix.SizeofIfInfomsg:])
	if err != nil {
		return "", err
	}

	var kind string
	for ad.Next() {
		if ad.Type() == unix.IFLA_LINKINFO {
			ad.Do(linkInfoKind(&kind))
		}
	}
	return kind, ad.Err()
}

// linkInfoKind reads IFLA_INFO_KIND from nested IFLA_LINKINFO attributes.
func linkInfoKind(kind *string) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return err
		}
		for ad.Next() {
			if ad.Type() == unix.IFLA_INFO_KIND {
				*kind = ad.String()
			}
		}
		return ad.Err()
	}
}

// parseRTNLInterfaces unpacks rtnetlink messages and returns WireGuard
// interface names.
func parseRTNLInterfaces(msgs []syscall.NetlinkMessage) ([]string, error) {
	var ifis []string
	for _, m := range msgs {
		// Only deal with link messages, and they must have an ifinfomsg
		// structure appear before the attributes.
		if m.Header.Type != unix.RTM_NEWLINK {
			continue
		}

		if len(m.Data) < unix.SizeofIfInfomsg {
			return nil, fmt.Errorf("wglinux: rtnetlink message is too short for ifinfomsg: %d", len(m.Data))
		}

		ad, err := netlink.NewAttributeDecoder(m.Data[syscall.SizeofIfInfomsg:])
		if err != nil {
			return nil, err
		}

		// Determine the interface's name and if it's a WireGuard device.
		var (
			ifi  string
			isWG bool
		)

		for ad.Next() {
			switch ad.Type() {
			case unix.IFLA_IFNAME:
				ifi = ad.String()
			case unix.IFLA_LINKINFO:
				ad.Do(isWGKind(&isWG))
			}
		}

		if err := ad.Err(); err != nil {
			return nil, err
		}

		if isWG {
			// Found one; append it to the list.
			ifis = append(ifis, ifi)
		}
	}

	return ifis, nil
}

// wgKind is the IFLA_INFO_KIND value for WireGuard devices.
const wgKind = "wireguard"

// isWGKind parses netlink attributes to determine if a link is a WireGuard
// or AmneziaWG device.
func isWGKind(ok *bool) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return err
		}

		for ad.Next() {
			if ad.Type() != unix.IFLA_INFO_KIND {
				continue
			}

			s := ad.String()
			// Check for both kinds
			if s == wgKind || s == amneziaKind {
				*ok = true
				return nil
			}
		}

		return ad.Err()
	}
}
