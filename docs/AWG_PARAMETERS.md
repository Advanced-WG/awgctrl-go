# AmneziaWG Parameter Reference

This document describes all AmneziaWG-specific obfuscation parameters supported
by the kernel module and this library.

All parameters are set on the **device** level (not per-peer) via `ConfigureDevice`.
Once set, they apply to all traffic on that interface.

---

## Junk Packets — Jc, Jmin, Jmax

Before each real WireGuard handshake, AmneziaWG sends a configurable number of
random-size UDP packets to make the traffic pattern unrecognisable to DPI systems.

| Parameter | Type | Kernel limit | Recommended | Description |
|---|---|---|---|---|
| `Jc` | int | 0–65535 | 0–10 | Number of junk packets sent before each handshake |
| `Jmin` | int | 0–65535 | 64–1024 | Minimum junk packet size in bytes |
| `Jmax` | int | 0–65534, ≥ Jmin | 64–1024 | Maximum junk packet size in bytes |

**Notes:**
- Setting `Jc = 0` disables junk packets entirely in the kernel; the
  `amneziawg-go` userspace daemon rejects `Jc`, `Jmin` and `Jmax` of 0
- Keep `Jmax` below the path MTU (1280 is safe everywhere), or junk packets get fragmented
- If `Jmin == Jmax`, the kernel increments `Jmax` by 1 automatically
- Larger values provide stronger obfuscation but increase handshake overhead
- `GenerateAmneziaParams()` generates Jc in the range 3–6 and packet sizes that resemble UDP application traffic

---

## Packet Padding — S1, S2, S3, S4

Random padding bytes are prepended to each WireGuard control packet type.
This changes the packet sizes so they no longer match the known WireGuard signature.

| Parameter | Type | Kernel limit | Recommended | Applies to packet | Base WireGuard size |
|---|---|---|---|---|---|
| `S1` | int | 0–65387 | 0–64 | Handshake Initiation | 148 bytes |
| `S2` | int | 0–65443 | 0–64 | Handshake Response | 92 bytes |
| `S3` | int | 0–65471 | 0–64 | Cookie Reply | 64 bytes |
| `S4` | int | 0–65503 | 0–32 | Transport Data | variable |

The kernel limit is 65535 minus the base message size. For S1–S3, staying under
the path MTU (for S1: 1280 − 148 = 1132) avoids fragmentation.

**Notes:**
- All four values should be **unique** to prevent correlation attacks
- Total packet sizes after padding must also be unique:
  - `S1+148 ≠ S2+92`
  - `S3+64 ≠ S1+148`
  - `S3+64 ≠ S2+92`
- `GenerateAmneziaParams()` enforces both rules automatically
- `S4` is added to every data packet, so it directly reduces the usable MTU; keep it small

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
| `<t>` | `<t>` | 4-byte Unix time in seconds (big-endian uint32) |
| `<rc N>` | `<rc 4>` | N random letters (a–z, A–Z) |
| `<rd N>` | `<rd 8>` | N random decimal digits |

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

`Validate()` rejects exactly what the kernel module rejects, so errors show up
before the netlink call instead of as a bare `EINVAL`. It does not enforce the
recommended ranges above; that is a policy decision for the application.

It checks:
- `Jc`, `Jmin`, `Jmax` are 16-bit; `Jmax < 65535`; `Jmin ≤ Jmax` when both are set
  (`Jmax = 0` turns junk packets off); `Jmin = Jmax = 65534` with junk packets on is
  rejected because the kernel then uses `Jmax + 1`
- `S1–S4` plus their base message size fit in 65535 bytes
- `H1–H4` are `N` or `N-M` (32-bit, `N ≤ M`) and do not overlap each other
- `I1–I5` only use known tags with valid arguments and describe at most 65535 bytes

`Validate()` sees only the fields that are set. The kernel checks a partial
update together with the device's current values, so e.g. `Jmin = 500` alone on a
device with `Jmax = 100`, or `H1 = 250-260` alone next to `H2 = 200-300`, is
rejected there. `Client.ConfigureDevice` covers this: when the config sets only
some of `Jc`/`Jmin`/`Jmax` or of `H1–H4`, it reads the device once and validates
the merged values, so the conflict is reported with a clear error. Configs that
set each group completely (or not at all) are not read.

Only the fields that are set are checked, so a partial update is validated on its
own. `wgtypes.ParseMagicHeader` and `wgtypes.InitPacketSize` expose the H and I
parsers for applications that need them.

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
