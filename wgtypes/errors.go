package wgtypes

import "errors"

// ErrUpdateOnlyNotSupported is returned due to missing kernel support of
// the PeerConfig UpdateOnly flag.
var ErrUpdateOnlyNotSupported = errors.New("the UpdateOnly flag is not supported by this platform")

// ErrAWGNotSupported is returned when AmneziaWG fields are sent to a device
// that is plain WireGuard.
var ErrAWGNotSupported = errors.New("the device is WireGuard, not AmneziaWG")

// ErrAWGVersionNotSupported is returned for an AmneziaWG kernel module whose
// netlink interface this library does not speak (e.g. AmneziaWG 3).
var ErrAWGVersionNotSupported = errors.New("the AmneziaWG netlink version is not supported")
