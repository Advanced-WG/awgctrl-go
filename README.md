# awgctrl-go

[![Linux Test](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/linux-test.yml/badge.svg)](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/linux-test.yml)
[![Static Analysis](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/Advanced-WG/awgctrl-go/actions/workflows/static-analysis.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/advanced-wg/awgctrl-go)](https://goreportcard.com/report/github.com/advanced-wg/awgctrl-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/advanced-wg/awgctrl-go.svg)](https://pkg.go.dev/github.com/advanced-wg/awgctrl-go)

A Go library for controlling **WireGuard** and **AmneziaWG** devices on Linux.

Fork of [WireGuard/wgctrl-go](https://github.com/WireGuard/wgctrl-go) extended
with complete AmneziaWG v2 support — reading and writing all AWG obfuscation
parameters via netlink, parameter validation, auto-generation, and userspace
daemon support.

## What's new compared to wgctrl-go

| Feature | wgctrl-go | awgctrl-go |
|---|---|---|
| Standard WireGuard | ✅ | ✅ |
| AmneziaWG — write params | ❌ | ✅ |
| AmneziaWG — **read** params | ❌ | ✅ |
| Peer-level AdvancedSecurity | ❌ | ✅ |
| Auto-generate AWG params | ❌ | ✅ |
| Validate AWG params | ❌ | ✅ |
| Userspace AWG daemon | ❌ | ✅ |
| context.Context API | ❌ | ✅ |
| Single netlink round-trip | ❌ | ✅ |

## Platform support

| Platform | Kernel WG | Kernel AWG | Userspace WG | Userspace AWG |
|---|---|---|---|---|
| Linux | ✅ | ✅ | ✅ | ✅ |
| FreeBSD | ✅ | ❌ | ✅ | ❌ |
| OpenBSD | ✅ | ❌ | ✅ | ❌ |
| Windows | ❌ | ❌ | ✅ | ❌ |

## Requirements

- Go 1.21 or later
- Linux kernel with AmneziaWG module (`modprobe amneziawg`), or `amneziawg-go` userspace daemon
- Root privileges or `CAP_NET_ADMIN` capability

This library works with **any AmneziaWG v2 kernel module**, including the
[upstream module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module).
For production use we recommend the
[patched fork](https://github.com/Advanced-WG/amneziawg-linux-kernel-module-awg)
which fixes netlink dump overflow with many peers, a cookie reply size bug,
sysfs race conditions, and adds DKMS/kernel 6.19+ compatibility.

AWG kernel and userspace support is Linux-only. Other platforms (FreeBSD, OpenBSD, Windows)
support standard WireGuard only.

## Installation

```bash
go get github.com/advanced-wg/awgctrl-go
```

## Quick start

### Read a device

```go
client, err := wgctrl.New()
if err != nil {
    log.Fatal(err)
}
defer client.Close()

device, err := client.Device(context.Background(), "awg0")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Interface: %s  IsAmnezia: %v\n", device.Name, device.IsAmnezia)
for _, peer := range device.Peers {
    fmt.Printf("Peer: %s  AWG: %v  RX: %d  TX: %d\n",
        peer.PublicKey, peer.AdvancedSecurity,
        peer.ReceiveBytes, peer.TransmitBytes)
}
```

### Enable AWG obfuscation

The simplest approach — all parameters are generated automatically:

```go
cfg := &wgtypes.Config{}
cfg.GenerateAmneziaParams()

if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}

client.ConfigureDevice(context.Background(), "awg0", *cfg)
```

### Add a peer with AWG

```go
pubKey, _ := wgtypes.ParseKey("base64encodedpublickey=")
_, allowedIP, _ := net.ParseCIDR("10.0.0.2/32")

cfg := wgtypes.Config{
    Peers: []wgtypes.PeerConfig{
        {
            PublicKey:        pubKey,
            AllowedIPs:       []net.IPNet{*allowedIP},
            AdvancedSecurity: true,
        },
    },
}

client.ConfigureDevice(context.Background(), "awg0", cfg)
```

## Documentation

- [AWG Parameter Reference](docs/AWG_PARAMETERS.md) — Jc, Jmin, Jmax, S1–S4, H1–H4, I1–I5 with limits, rules and examples
- [Peer Advanced Security](docs/ADVANCED_SECURITY.md) — how the kernel determines per-peer AWG status
- [Examples](docs/EXAMPLES.md) — practical usage examples
- [pkg.go.dev](https://pkg.go.dev/github.com/advanced-wg/awgctrl-go) — full API reference

## License

MIT — Copyright (C) 2018-2022 Matt Layher, 2025 Advanced-WG, V. Bantserov.
See [LICENSE.md](LICENSE.md).
