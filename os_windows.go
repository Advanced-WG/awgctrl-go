//go:build windows
// +build windows

package wgctrl

import (
	"github.com/advanced-wg/awgctrl-go/internal/wginternal"
	"github.com/advanced-wg/awgctrl-go/internal/wguser"
	"github.com/advanced-wg/awgctrl-go/internal/wgwindows"
)

// newClients configures wginternal.Clients for Windows systems.
func newClients() ([]wginternal.Client, error) {
	var clients []wginternal.Client

	// Windows has an in-kernel WireGuard implementation.
	kc := wgwindows.New()
	clients = append(clients, kc)

	uc, err := wguser.New()
	if err != nil {
		return nil, err
	}

	clients = append(clients, uc)
	return clients, nil
}
