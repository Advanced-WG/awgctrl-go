# Examples

Practical usage examples for awgctrl-go.

---

## Basic WireGuard — read all devices

```go
package main

import (
    "context"
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

    devices, err := client.Devices(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    for _, d := range devices {
        fmt.Printf("Interface: %s  Type: %s  Port: %d\n",
            d.Name, d.Type, d.ListenPort)
        fmt.Printf("  Public key: %s\n", d.PublicKey)
        fmt.Printf("  Peers: %d\n", len(d.Peers))

        if d.IsAmnezia {
            fmt.Printf("  AWG: Jc=%d Jmin=%d Jmax=%d\n",
                d.Jc, d.Jmin, d.Jmax)
        }
    }
}
```

---

## Configure AWG with auto-generated parameters

The simplest way to enable AWG obfuscation — all parameters are generated
automatically with DPI-resistant values.

```go
package main

import (
    "context"
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
    cfg.GenerateAmneziaParams()

    if err := cfg.Validate(); err != nil {
        log.Fatal(err)
    }

    if err := client.ConfigureDevice(context.Background(), "awg0", *cfg); err != nil {
        log.Fatal(err)
    }

    log.Println("AWG configured successfully")
}
```

---

## Configure AWG with manual parameters

For exact control over obfuscation parameters, e.g. when you need to match
parameters with an existing client configuration.

```go
package main

import (
    "context"
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
        // Junk packets before handshake
        Jc:   intPtr(4),
        Jmin: intPtr(80),
        Jmax: intPtr(160),

        // Packet padding (all values must be unique)
        S1: intPtr(30),  // Initiation
        S2: intPtr(40),  // Response
        S3: intPtr(50),  // Cookie
        S4: intPtr(8),   // Transport

        // Magic header ranges (must not overlap)
        H1: strPtr("200000000-280000000"),
        H2: strPtr("400000000-480000000"),
        H3: strPtr("600000000-680000000"),
        H4: strPtr("350000000-430000000"),

        // Init packet chain (AWG 2.0) — omit to use AWG 1.0 mode
        I1: strPtr("<r 20>"),
        I2: strPtr("<r 15>"),
        I3: strPtr("<r 12>"),
        I4: strPtr("<r 18>"),
        I5: strPtr("<r 14>"),
    }

    if err := cfg.Validate(); err != nil {
        log.Fatal(err)
    }

    if err := client.ConfigureDevice(context.Background(), "awg0", cfg); err != nil {
        log.Fatal(err)
    }
}
```

---

## Add peers with AWG obfuscation

```go
package main

import (
    "context"
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

    endpoint, err := net.ResolveUDPAddr("udp", "192.0.2.1:51820")
    if err != nil {
        log.Fatal(err)
    }

    _, allowedIP, _ := net.ParseCIDR("10.0.0.2/32")

    cfg := wgtypes.Config{
        Peers: []wgtypes.PeerConfig{
            {
                PublicKey:        pubKey,
                Endpoint:         endpoint,
                AllowedIPs:       []net.IPNet{*allowedIP},
                AdvancedSecurity: true, // expect AWG-obfuscated traffic from this peer
            },
        },
    }

    if err := client.ConfigureDevice(context.Background(), "awg0", cfg); err != nil {
        log.Fatal(err)
    }
}
```

---

## Monitor peer connections

Check which peers are actively using AWG obfuscation and their traffic stats.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    wgctrl "github.com/advanced-wg/awgctrl-go"
)

func main() {
    client, err := wgctrl.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    for {
        device, err := client.Device(context.Background(), "awg0")
        if err != nil {
            log.Fatal(err)
        }

        for _, peer := range device.Peers {
            awg := "WG"
            if peer.AdvancedSecurity {
                awg = "AWG"
            }

            lastHS := "never"
            if !peer.LastHandshakeTime.IsZero() {
                lastHS = time.Since(peer.LastHandshakeTime).Round(time.Second).String() + " ago"
            }

            fmt.Printf("[%s] %s  RX: %d bytes  TX: %d bytes  Handshake: %s\n",
                awg,
                peer.PublicKey,
                peer.ReceiveBytes,
                peer.TransmitBytes,
                lastHS,
            )
        }

        time.Sleep(5 * time.Second)
    }
}
```

---

## Context cancellation

All operations support `context.Context` for timeout and cancellation.

```go
package main

import (
    "context"
    "log"
    "time"

    wgctrl "github.com/advanced-wg/awgctrl-go"
)

func main() {
    client, err := wgctrl.New()
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Timeout after 2 seconds
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    device, err := client.Device(ctx, "awg0")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Device: %s", device.Name)
}
```

---

## Remove a peer

```go
pubKey, _ := wgtypes.ParseKey("base64encodedpublickey=")

cfg := wgtypes.Config{
    Peers: []wgtypes.PeerConfig{
        {
            PublicKey: pubKey,
            Remove:    true,
        },
    },
}

client.ConfigureDevice(ctx, "awg0", cfg)
```

---

## Replace all peers

```go
cfg := wgtypes.Config{
    ReplacePeers: true,
    Peers: []wgtypes.PeerConfig{
        // only these peers will exist after this call
        { PublicKey: newKey, AllowedIPs: []net.IPNet{*cidr} },
    },
}

client.ConfigureDevice(ctx, "awg0", cfg)
```
