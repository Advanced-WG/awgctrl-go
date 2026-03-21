//go:build !linux && !openbsd && !windows && !freebsd
// +build !linux,!openbsd,!windows,!freebsd

package wgctrl

import (
	"github.com/advanced-wg/awgctrl-go/internal/wginternal"
	"github.com/advanced-wg/awgctrl-go/internal/wguser"
)

// newClients configures wginternal.Clients for systems which only support
// userspace WireGuard implementations.
func newClients() ([]wginternal.Client, error) {
	c, err := wguser.New()
	if err != nil {
		return nil, err
	}

	return []wginternal.Client{c}, nil
}
