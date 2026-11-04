# On-device IOKit fuzzing — Phase 0–2 (iOS 27.0.1)

A hands-on experiment: how much attack surface can a **sandboxed app** reach through IOKit on a
current device, and does blind black-box fuzzing find anything? Honest answer up front: **0 crashes
across 3.45M calls** — current 27.0.1 is hardened against this approach. The value is the
methodology, the safety engineering, and the recovered static dispatch tables.

## The instrumentation app

A SwiftUI app (the author's own, run on the author's own device) that, from the app sandbox:
enumerates IOKit services (`IOServiceMatching("IOService")`), probes `IOServiceOpen` connection
types, and drives seeded, reproducible input through `IOConnectCallMethod`, logging JSONL.

**Safety engineering** (because a fuzzer *can* panic a device by design):
- `pending.json` breadcrumb `fsync`'d **before** each call, truncated after → a panic leaves it
  non-empty → promoted to `suspects.jsonl` on next launch (the Phase-0→1 bridge).
- **Adaptive blocklist** — a crash's `(class,type,selector)` is extracted and never exercised again
  (forward progress only).
- **Circuit breaker** — disables Start after N consecutive crashes until manual reset.
- **Staged modes** (Enumerate → Open → SigProbe → Call → Content), default = zero-risk Enumerate.
- **Thermal guard** — pauses on serious/critical thermal state.
- Hard caps on struct size / scalar count; conservative class denylist (NVRAM/power).

## Results

| Phase | Result |
|---|---|
| Enumerate | 1430 service instances / 343 unique classes |
| Open | 108 openable (class×type) across 18 classes (AGXAccelerator, AppleJPEGDriver, AppleM2ScalerCSC, IOSurfaceRoot, AppleKeyStore, …) |
| Call (blind) | **3.45M calls, 0 crashes, 0 hangs**; ~89% bounced off the `IOUserClient::externalMethod` arg-shape gate before reaching driver code |
| SigProbe | the only dynamically-discoverable methods were **getters** (succeed on empty input) → no parse surface |
| Content | malformed content in correctly-shaped calls → still 0 crashes |

**Lesson:** blind black-box IOKit fuzzing from the sandbox is low-yield on hardened 27.0.1 — the
arg-shape gate + getters dominate, and the real parse methods need **exact (scalarCount,
structSize)** shapes that only a **static** dispatch-table recovery provides.

## Static dispatch tables (the useful artifact)

Recovered `IOExternalMethodDispatch` tables from the 27.0.1 kernelcache for the high-value user
clients, giving the exact arg shapes of the real parse surface:

- **IOSurfaceRoot** (IOUserClient2022, 60 selectors) — variable-struct input methods identified.
- **AppleJPEGDriver** (10 selectors) — `sel 4/5 = (0, 4096)`, `6/7 = (0, 3488)` parsers.
- **AppleM2ScalerCSCDriver** — all scalar-in, no struct input → confirmed getter-class.
- **AppleSEPKeyStore** — switch-based, validates in handlers (no static table).

These shapes are what a *targeted* content-fuzz would need; the blind runs showed why they are
necessary. The on-device data confirms 27.0.1's IOKit sandbox surface is well-gated.

### Drilled detail — the wrapper validates, two `VAR` workers are bounded

The `IOExternalMethodDispatch2022` wrapper enforces each selector's `(scalarInputCount,
structInputSize)` *before* the handler runs; the fixed-size selectors are rejected pre-parse on any
mismatch (this is the ~89% arg-gate). The remaining risk is the `VAR` (variable-struct) selectors,
where the handler itself must bound the input. Two of them were drilled to the instruction level and
are **bounded**:

- **sel 9** (`VAR` in): wrapper `0xfffffff00a34bd74` floors `structInputSize ≥ 0xd`, then its worker
  `0xfffffff00a34f600` hands the payload to a length-aware deserializer `0xfffffff00b28f330` as an
  explicit `(ptr = structInput+0xc, len = structInputSize−0xc)` pair, where `len` is computed as a
  **pointer difference from the real buffer extent** (`end − start`), not a raw length field.
- **sel 26** (`VAR` in): wrapper `0xfffffff00a34c690` floors `structInputSize ≥ 0xd`
  (`ccmp w25, #0xd`, with `w25 = [args+0x38]`), passes the size in `x3` (`mov x3, x25`) to worker
  `0xfffffff00a3529c4`, which reads exactly `structInput[structInputSize−1]` (a trailing-NUL check) —
  in-bounds because the floor guarantees the index `0xc + (size−0xd) = size−1 < size`.

Handler pointers were decoded from **raw** `__const` bytes
(`vaddr = 0xfffffff007004000 + (raw & 0xffffffff)`), since `ipsw macho dump --addr` can mis-resolve
them. **AppleJPEGDriver** sel 4/5/6/7 take fixed struct sizes (`0x1000`/`0xda0`) and range-check the
dimension/resolution fields (component ≤ `0xff`, dimension high-word = 0 ⇒ ≤ `0xffff`) with the
giveaway error string *"i/o sizes are illegal … Horz/Vert Resolutions are not set"*.

## Evidence

Every claim above has a reproduction command + real disasm pulled from the 27.0.1 kernelcache:

- [`evidence/iosurface-dispatch-table.md`](evidence/iosurface-dispatch-table.md) — all 60 selectors
  decoded from raw bytes (the authoritative handler VAs + `(scalarIn, structIn)` shapes).
- [`evidence/iosurface-sel9-deserializer.md`](evidence/iosurface-sel9-deserializer.md) — sel 9 floor
  + bounded `(ptr, len)` slice into the deserializer.
- [`evidence/iosurface-sel26-lastbyte.md`](evidence/iosurface-sel26-lastbyte.md) — sel 26 floor,
  `mov x3, x25` marshalling, and the bounded last-byte read.
- [`evidence/applejpeg-dispatch-table.md`](evidence/applejpeg-dispatch-table.md) — the 10-selector
  table, all fixed struct sizes.
- [`evidence/applejpeg-dimension-bound.md`](evidence/applejpeg-dimension-bound.md) — the sel-4
  worker's dimension range-checks + the diagnostic string.

## Code & experiments

- [`code/`](code/) — the fuzzer C API contract (`FuzzCore.h`) + the safety-model write-up.
- [`experiments/results.md`](experiments/results.md) — the measured run values (1430/108/3.45M/0),
  the ~89% arg-gate breakdown, and the recovered static `IOExternalMethodDispatch` tables.
