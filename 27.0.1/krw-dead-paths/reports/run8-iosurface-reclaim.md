# Run 8: IOSurface UAF Reclaim Failure

**Date:** 2026-11-19
**Device:** iPhone 17,2 (A17 Pro, D94AP)
**Build:** 24A446
**Paths:** L1 (reclaim spray)

## Summary

CVE-2026-112477 IOSurface Registry UAF **triggers reliably** on iOS 27.0.1 but the
reclaim spray **does not reach the freed slot**. Result: `triggered=true, reclaimed=false`.

## Mechanism

The UAF chain works:
1. **sel17** (async register) → `0x0` SUCCESS
2. **sel17** (duplicate) → `0xe00002c9` InternalError (expected)
3. **sel18** (sync deregister) → `0x0` SUCCESS
4. **sel17** (re-register) → `0x0` SUCCESS — **27.0.1 vulnerable** (blocked on 27.2)

All four trigger phases complete:
- V_TEARREG: 1584 registrations, 1584 OK
- V_LOCKDEG: 200 iterations survived
- REREG+DUALREF: 100/100 OK, 0 failures
- COMBINED: 2823 thread operations across 300 iterations

## Failure Point

The freed `kalloc.1024` slot from the deregistered IOSurface node is not filled by
the reclaim spray of 256 IOSurfaces. The slot remains stale.

**Why:**
- `kalloc_type<IOSurface>` zone isolation means only objects of the exact same type
  fill freed slots
- The spray creates IOSurface objects in `kalloc_type<IOSurface>.1024` but the freed
  node may be in a different sub-bucket or magazine
- A17 Pro has **no kernel MTE** — silent UAF produces no observable signal to confirm
  whether reclaim succeeded

## A17 Pro Specifics

```
A17 Pro (no kMTE): silent UAF = no observable signal
```

Without MTE color tags, there is no way to distinguish:
- UAF triggered but not reclaimed (freed slot still stale)
- UAF triggered and reclaimed (controlled data in slot)
- UAF not triggered at all (no dangling reference created)

The only signal is `triggered=1` from the re-registration succeeding.

## Status

**triggered=true, reclaimed=false** — the UAF is real and reproducible, but exploitation
requires either:
1. Better reclaim timing (spray closer to deregistration)
2. Larger spray volume to saturate the magazine/depot
3. Zone GC to consolidate pages and increase overlap probability
4. A stale-read path that extracts data from the freed slot before reclaim
