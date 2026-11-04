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

## Code & experiments

- [`code/`](code/) — the fuzzer C API contract (`FuzzCore.h`) + the safety-model write-up.
- [`experiments/results.md`](experiments/results.md) — the measured run values (1430/108/3.45M/0),
  the ~89% arg-gate breakdown, and the recovered static `IOExternalMethodDispatch` tables.
