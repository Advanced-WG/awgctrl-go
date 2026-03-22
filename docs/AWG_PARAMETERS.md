# AmneziaWG Parameter Reference

This document describes all AmneziaWG-specific obfuscation parameters supported
by the kernel module and this library.

All parameters are set on the **device** level (not per-peer) via `ConfigureDevice`.
Once set, they apply to all traffic on that interface.

---

## Junk Packets — Jc, Jmin, Jmax

Before each real WireGuard handshake, AmneziaWG sends a configurable number of
random-size UDP packets to make the traffic pattern unrecognisable to DPI systems.

| Parameter | Type | Range | Description |
|---|---|---|---|
| `Jc` | int | 0–10 | Number of junk packets sent before each handshake |
| `Jmin` | int | 64–1024 | Minimum junk packet size in bytes |
| `Jmax` | int | 64–1024 | Maximum junk packet size in bytes (must be ≥ Jmin) |

**Notes:**
- Setting `Jc = 0` disables junk packets entirely
- If `Jmin == Jmax`, the kernel increments `Jmax` by 1 automatically
- Larger values provide stronger obfuscation but increase handshake overhead
- `GenerateAmneziaParams()` generates Jc in the range 3–6 and packet sizes that resemble UDP application traffic

---

## Packet Padding — S1, S2, S3, S4

Random padding bytes are prepended to each WireGuard control packet type.
This changes the packet sizes so they no longer match the known WireGuard signature.

| Parameter | Type | Range | Applies to packet | Base WireGuard size |
|---|---|---|---|---|
| `S1` | int | 0–64 | Handshake Initiation | 148 bytes |
| `S2` | int | 0–64 | Handshake Response | 92 bytes |
| `S3` | int | 0–64 | Cookie Reply | 64 bytes |
| `S4` | int | 0–32 | Transport Data | variable |

**Notes:**
- All four values should be **unique** to prevent correlation attacks
- Total packet sizes after padding must also be unique:
  - `S1+148 ≠ S2+92`
  - `S3+64 ≠ S1+148`
  - `S3+64 ≠ S2+92`
- `GenerateAmneziaParams()` enforces both rules automatically
- `S4` has a smaller range (0–32) to preserve MTU headroom for data packets

---

## Magic Headers — H1, H2, H3, H4

Each WireGuard packet type has a 4-byte message type field. AmneziaWG replaces
these fixed values with random values drawn from configured ranges, so the packets
no longer carry recognisable WireGuard message type identifiers.

| Parameter | Type | Applies to packet |
|---|---|---|
| `H1` | string | Handshake Initiation |
| `H2` | string | Handshake Response |
| `H3` | string | Cookie Reply |
| `H4` | string | Transport Data |

**Format:**

A value can be either a single number or a range:

```
"123456789"           — exact value (same header every time)
"100000000-200000000" — range (random value within range per packet)
```

**Notes:**
- Ranges provide stronger obfuscation because the header changes with every packet
- The four header ranges must **not overlap**
- Values must be below `2147483647` (MaxInt32) for compatibility with some clients
- `GenerateAmneziaParams()` generates 4 non-overlapping ranges and then **shuffles**
  their assignment to H1–H4, preventing heuristic DPI matching based on ordering

---

## Init Packet Chain — I1, I2, I3, I4, I5 (AWG 2.0)

The init packet chain is an AWG 2.0 feature that customises the structure of
handshake initiation packets to mimic other protocols (e.g. TLS, DTLS).

| Parameter | Type | Description |
|---|---|---|
| `I1` | string | First segment descriptor |
| `I2` | string | Second segment descriptor |
| `I3` | string | Third segment descriptor |
| `I4` | string | Fourth segment descriptor |
| `I5` | string | Fifth segment descriptor |

**Behaviour:**
- If `I1` is absent (nil/empty), the entire chain is skipped and AmneziaWG behaves
  as version 1.0
- When `I1` is present, all five fields should be set

**Tag syntax:**

Each field is a string composed of one or more tags that describe packet segments:

| Tag | Example | Description |
|---|---|---|
| `<r N>` | `<r 20>` | N random bytes |
| `<b 0xHEX>` | `<b 0xdeadbeef>` | Literal bytes in hex |
| `<c>` | `<c>` | 4-byte packet counter (big-endian uint32) |
| `<t VAL>` | `<t 1>` | Timestamp-based field |
| `<rc VAL>` | `<rc 4>` | Count-based random bytes |
| `<rd VAL>` | `<rd 8>` | Deterministic random bytes |

Tags can be combined: `"<r 10><b 0xff><c>"`

`GenerateAmneziaParams()` uses `<r N>` (random bytes) for all five fields, which is
the simplest and most DPI-resistant option.

---

## Validation

Use `Config.Validate()` to check all parameters before sending to the kernel:

```go
cfg := &wgtypes.Config{
    Jc:   intPtr(5),
    Jmin: intPtr(100),
    Jmax: intPtr(200),
}

if err := cfg.Validate(); err != nil {
    log.Fatal(err)
}
```

`Validate()` checks:
- `Jc` is in range 0–10
- `Jmin` and `Jmax` are in range 64–1024
- `Jmin ≤ Jmax`
- `S1–S3` are in range 0–64
- `S4` is in range 0–32

---

## Auto-generation

`Config.GenerateAmneziaParams()` fills all parameters with cryptographically
randomised values that satisfy all kernel constraints and DPI-resistance rules:

```go
cfg := &wgtypes.Config{}
cfg.GenerateAmneziaParams()

if err := cfg.Validate(); err != nil {
    // This should never happen with generated params
    log.Fatal(err)
}

client.ConfigureDevice(ctx, "awg0", *cfg)
```

The generated values are optimised for:
- Resembling UDP application traffic (junk packet sizes)
- No fixed packet size signatures (unique padding values)
- No predictable header ordering (shuffled H1–H4 ranges)
- Full AWG 2.0 compatibility (I1–I5 present)
