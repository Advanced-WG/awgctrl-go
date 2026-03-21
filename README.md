# awgctrl-go

[![Linux Test](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/linux-test.yml/badge.svg)](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/linux-test.yml)
[![Static Analysis](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/static-analysis.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/advanced-wg/awgctrl-go)](https://goreportcard.com/report/github.com/advanced-wg/awgctrl-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/advanced-wg/awgctrl-go.svg)](https://pkg.go.dev/github.com/advanced-wg/awgctrl-go)

A Go library for controlling **WireGuard** and **AmneziaWG** devices on Linux.

This is a fork of [WireGuard/wgctrl-go](https://github.com/WireGuard/wgctrl-go) extended with complete AmneziaWG support — reading and writing AWG obfuscation parameters via netlink, parameter validation, and userspace daemon support.

## Installation

```bash
go get github.com/advanced-wg/awgctrl-go
```

Requires Go 1.21 or later. Linux only for AWG kernel support; other platforms support standard WireGuard only.

## What's different from wgctrl-go

| Feature | wgctrl-go | awgctrl-go |
|---|---|---|
| Standard WireGuard | ✅ | ✅ |
| AmneziaWG — write params | ❌ | ✅ |
| AmneziaWG — **read** params | ❌ | ✅ |
| Auto-generate AWG params | ❌ | ✅ |
| Validate AWG params | ❌ | ✅ |
| Userspace AWG daemon support | ❌ | ✅ |
| Single netlink round-trip | ❌ | ✅ |

## Usage

### Read a device

```go
package main

import (
    "fmt"
    "log"

    wgctrl "github.com/advanced-wg/awgctrl-go"
)

func main() {
    client, err := wgctrl.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    device, err := client.Device("awg0")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Name:      %s\n", device.Name)
    fmt.Printf("IsAmnezia: %v\n", device.IsAmnezia)
    fmt.Printf("PublicKey: %s\n", device.PublicKey)

    if device.IsAmnezia {
        fmt.Printf("Jc=%d Jmin=%d Jmax=%d\n", device.Jc, device.Jmin, device.Jmax)
        fmt.Printf("S1=%d S2=%d S3=%d S4=%d\n", device.S1, device.S2, device.S3, device.S4)
        fmt.Printf("H1=%s H2=%s H3=%s H4=%s\n", device.H1, device.H2, device.H3, device.H4)
    }

    for _, peer := range device.Peers {
        fmt.Printf("Peer: %s  RX=%d  TX=%d  LastHandshake=%s\n",
            peer.PublicKey, peer.ReceiveBytes, peer.TransmitBytes, peer.LastHandshakeTime)
    }
}
```

### Configure with auto-generated AWG parameters

```go
package main

import (
    "log"

    wgctrl "github.com/advanced-wg/awgctrl-go"
    "github.com/advanced-wg/awgctrl-go/wgtypes"
)

func main() {
    client, err := wgctrl.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    cfg := &wgtypes.Config{}

    // Populate with randomized, DPI-resistant obfuscation values.
    cfg.GenerateAmneziaParams()

    // Always validate before applying.
    if err := cfg.Validate(); err != nil {
        log.Fatal(err)
    }

    if err := client.ConfigureDevice("awg0", *cfg); err != nil {
        log.Fatal(err)
    }
}
```

### Configure with manual AWG parameters

```go
package main

import (
    "log"

    wgctrl "github.com/advanced-wg/awgctrl-go"
    "github.com/advanced-wg/awgctrl-go/wgtypes"
)

func intPtr(i int) *int    { return &i }
func strPtr(s string) *string { return &s }

func main() {
    client, err := wgctrl.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    cfg := wgtypes.Config{
        Jc:   intPtr(4),
        Jmin: intPtr(80),
        Jmax: intPtr(160),
        S1:   intPtr(30),
        S2:   intPtr(40),
        S3:   intPtr(50),
        S4:   intPtr(8),
        H1:   strPtr("200000000-280000000"),
        H2:   strPtr("400000000-480000000"),
        H3:   strPtr("600000000-680000000"),
        H4:   strPtr("350000000-430000000"),
    }

    if err := cfg.Validate(); err != nil {
        log.Fatal(err)
    }

    if err := client.ConfigureDevice("awg0", cfg); err != nil {
        log.Fatal(err)
    }
}
```

### Add a peer

```go
package main

import (
    "log"
    "net"

    wgctrl "github.com/advanced-wg/awgctrl-go"
    "github.com/advanced-wg/awgctrl-go/wgtypes"
)

func main() {
    client, err := wgctrl.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    pubKey, err := wgtypes.ParseKey("base64encodedpublickey=")
    if err != nil {
        log.Fatal(err)
    }

    _, allowedIP, err := net.ParseCIDR("10.0.0.2/32")
    if err != nil {
        log.Fatal(err)
    }

    cfg := wgtypes.Config{
        Peers: []wgtypes.PeerConfig{
            {
                PublicKey:  pubKey,
                AllowedIPs: []net.IPNet{*allowedIP},
            },
        },
    }

    if err := client.ConfigureDevice("awg0", cfg); err != nil {
        log.Fatal(err)
    }
}
```

## AWG parameter reference

| Param | Range | Description |
|---|---|---|
| `Jc` | 0–10 | Number of junk packets sent before each handshake |
| `Jmin` | 64–1024 | Minimum junk packet size in bytes |
| `Jmax` | 64–1024 | Maximum junk packet size in bytes (must be ≥ Jmin) |
| `S1` | 0–64 | Padding bytes prepended to Initiation packet |
| `S2` | 0–64 | Padding bytes prepended to Response packet |
| `S3` | 0–64 | Padding bytes prepended to Cookie packet |
| `S4` | 0–32 | Padding bytes prepended to Transport packet |
| `H1` | string or range | Magic header for Initiation (e.g. `"123456789"` or `"100000000-200000000"`) |
| `H2` | string or range | Magic header for Response |
| `H3` | string or range | Magic header for Cookie |
| `H4` | string or range | Magic header for Transport |
| `I1`–`I5` | string | Custom init packet chain (AWG 2.0). If I1 is absent, the entire chain is skipped and AWG behaves as 1.0. |

## Platform support

| Platform | Kernel WG | Kernel AWG | Userspace WG | Userspace AWG |
|---|---|---|---|---|
| Linux | ✅ | ✅ | ✅ | ✅ |
| FreeBSD | ✅ | ❌ | ✅ | ❌ |
| OpenBSD | ✅ | ❌ | ✅ | ❌ |
| Windows | ❌ | ❌ | ✅ | ❌ |

AWG kernel support requires the [AmneziaWG kernel module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module).
AWG userspace support requires the [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) daemon.

## Requirements

- Linux kernel with AmneziaWG module loaded (`modprobe amneziawg`), or
- `amneziawg-go` userspace daemon running
- Root privileges or `CAP_NET_ADMIN` capability

## License

MIT — Copyright (C) 2018-2022 Matt Layher. See [LICENSE.md](LICENSE.md).

## AmneziaWG advanced security per peer

The kernel marks each peer with an `AdvancedSecurity` flag that indicates whether AWG obfuscation is active for that peer. You must set it explicitly when adding/updating peers on an AWG device:

```go
pubKey, _ := wgtypes.ParseKey("base64encodedpublickey=")
_, allowedIP, _ := net.ParseCIDR("10.0.0.2/32")

cfg := wgtypes.Config{
    Peers: []wgtypes.PeerConfig{
        {
            PublicKey:        pubKey,
            AllowedIPs:       []net.IPNet{*allowedIP},
            AdvancedSecurity: true, // enable AWG obfuscation for this peer
        },
    },
}
client.ConfigureDevice("awg0", cfg)
```

When reading a device, `peer.AdvancedSecurity` reflects the kernel's current state for each peer.

## I1–I5 tag syntax reference

The kernel supports the following tags in I1–I5 strings (tags can be combined):

| Tag | Example | Description |
|---|---|---|
| `<r N>` | `<r 20>` | N random bytes |
| `<b 0xHEX>` | `<b 0xdeadbeef>` | Literal bytes (hex-encoded) |
| `<c>` | `<c>` | 4-byte packet counter (big-endian uint32) |
| `<t VAL>` | `<t 1>` | Timestamp-based field |
| `<rc VAL>` | `<rc 4>` | Count-based random bytes |
| `<rd VAL>` | `<rd 8>` | Deterministic random bytes |

Tags can be combined in a single field: `"<r 10><b 0xff><c>"`.

`GenerateAmneziaParams()` uses `<r N>` only, which is the simplest and most DPI-resistant option.
