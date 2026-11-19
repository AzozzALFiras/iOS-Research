# iin_object Obfuscation — iOS 27.0.1

**Device:** iPhone 17,2 (A17 Pro, D94AP)
**Build:** 24A446
**Date:** 2026-11-19 (Run 8)

## Claim

`mach_port_space_info()` returns `iin_object` values that are **per-entry obfuscated**,
not plain kernel pointers and not simple XOR-masked. The obfuscation scheme prevents
deriving real port kaddrs from userspace.

## Evidence

### 1. Diffs between adjacent ports are random

The escalation module allocated 4096 ports and read their `iin_object` values via
`mach_port_space_info()`. Consecutive port kaddrs in a slab zone should differ by
`element_size` (230 bytes = 0xE6). Instead:

```
diff 0x35f count=1
diff 0xa63 count=1
diff 0xf3f count=1
diff 0x7ef count=1
diff 0xbe7 count=1
diff 0xcd0 count=1
diff 0x8ba count=1
diff 0x505 count=1
diff 0x852 count=1
diff 0xb03 count=1
```

No diff value repeats. Expected `0xE6` appears zero times. This rules out:
- Plain pointers (would show consistent Δ=0xE6)
- Global XOR mask (would preserve Δ between entries)
- Per-page XOR (adjacent entries on same page would still show correct Δ)

### 2. Low-3 bits analysis

From Run 7 raw data, 5 consecutive `iin_object` values:

| Entry | iin_object | Low 3 bits |
|-------|-----------|------------|
| 1 | 0x1cbe160c | 4 |
| 2 | 0x6aecc5a5 | 5 |
| 3 | 0xba8f0826 | 6 |
| 4 | 0x606e55af | 7 |
| 5 | 0x9b7273d2 | 2 |

Real port kaddrs in `ipc.ports` zone are always 2-byte aligned (low bit = 0).
The set {4,5,6,7,2} proves per-entry manipulation that disturbs alignment bits.

### 3. Same-page detection unreliable

The module attempted to find same-page port pairs (kaddr & ~0x3FFF match).
Only 29 of 4008 pairs appeared to share a page. One "page" showed 3,497 ports —
physically impossible for a 16KB page with 230-byte elements (max 71).

```
page[511] 0xfffffff02634c000 ports=3497 ★
⚠ IMPOSSIBLE: 3497 ports on one 16KB page (max=71) — kaddrs from space_info are UNRELIABLE
```

## Conclusion

`iin_object` on iOS 27.0.1 uses a **per-entry encryption scheme** (likely keyed hash
or per-entry XOR with entry-index-dependent key). This blocks:
- Direct kaddr extraction from `mach_port_space_info()`
- Zone page layout mapping via adjacent-port differencing
- Zone GC detection via page membership analysis

**Impact on jailbreak chain:** The IPC UAF escalation module cannot determine real
port kaddrs, making zone GC → pipe overlay impossible without an independent kaddr oracle.
