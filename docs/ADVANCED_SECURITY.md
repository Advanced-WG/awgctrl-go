# Peer Advanced Security

This document explains the `AdvancedSecurity` field on `Peer` and `PeerConfig`
and how the kernel determines its value.

---

## What it means

`Peer.AdvancedSecurity` is a **read-only indicator** set by the kernel.
It is `true` when a peer connected using a valid AWG-obfuscated handshake.

Specifically, the kernel sets it when **both** conditions are met:

1. The device has AWG obfuscation active (`Jc`, `H1`–`H4`, etc. are configured)
2. The received handshake packet carried a **valid magic header** — meaning the
   remote peer is also running an AWG client with matching parameters

If a standard WireGuard client connects to an AWG server, `AdvancedSecurity`
will be `false` for that peer because its handshake packet will not carry a
valid AWG magic header.

---

## Reading the value

```go
device, err := client.Device(ctx, "awg0")
if err != nil {
    log.Fatal(err)
}

for _, peer := range device.Peers {
    if peer.AdvancedSecurity {
        fmt.Printf("Peer %s: connected with AWG obfuscation\n", peer.PublicKey)
    } else {
        fmt.Printf("Peer %s: connected without AWG obfuscation\n", peer.PublicKey)
    }
}
```

---

## Setting the value on PeerConfig

`PeerConfig.AdvancedSecurity` tells the kernel to **expect** AWG-obfuscated
traffic from this peer and to apply the device's obfuscation parameters when
communicating with it.

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

client.ConfigureDevice(ctx, "awg0", cfg)
```

**Important:** Setting `PeerConfig.AdvancedSecurity = true` only has effect if
the device itself has AWG parameters configured. If the device has no AWG params,
the flag is ignored by the kernel.

---

## Kernel implementation detail

From `noise.c` in the AmneziaWG kernel module:

```c
bool advanced_security = wg->advanced_security &&
    mh_validate(SKB_TYPE_LE32(skb), &wg->headers[MSGIDX_HANDSHAKE_INIT]);

peer->advanced_security = advanced_security;
```

The kernel validates the magic header of the incoming handshake initiation packet
against the configured `H1` range. If it falls within the range, the peer is
marked as AWG-capable.

---

## Netlink protocol

When reading a device (`WG_CMD_GET_DEVICE`), the kernel sends for each peer:

- `WGPEER_A_FLAGS` with `WGPEER_F_HAS_ADVANCED_SECURITY` bit always set
  (indicates the device supports AWG — not that the peer uses it)
- `WGPEER_A_ADVANCED_SECURITY` NLA_FLAG — present only if `peer->advanced_security`
  is true

When writing a peer (`WG_CMD_SET_DEVICE`), to enable AWG for a peer:

- Set `WGPEER_F_HAS_ADVANCED_SECURITY` in `WGPEER_A_FLAGS`
- Include `WGPEER_A_ADVANCED_SECURITY` NLA_FLAG

This library handles both automatically via `PeerConfig.AdvancedSecurity`.
