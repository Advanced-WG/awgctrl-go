//go:build openbsd
// +build openbsd

package wgctrl

import (
	"github.com/awg-go/awgctrl-go/internal/wginternal"
	"github.com/awg-go/awgctrl-go/internal/wgopenbsd"
	"github.com/awg-go/awgctrl-go/internal/wguser"
)

// newClients configures wginternal.Clients for OpenBSD systems.
func newClients() ([]wginternal.Client, error) {
	var clients []wginternal.Client

	// OpenBSD has an in-kernel WireGuard implementation. Determine if it is
	// available and make use of it if so.
	kc, ok, err := wgopenbsd.New()
	if err != nil {
		return nil, err
	}
	if ok {
		clients = append(clients, kc)
	}

	uc, err := wguser.New()
	if err != nil {
		return nil, err
	}

	clients = append(clients, uc)
	return clients, nil
}
