# IOKit fuzzing — experiment log & measured values (27.0.1, iPhone17,2)

Device confirmed via logs: `iPhone17,2 / D94AP / 24A446 / 27.0.1`. Logs pulled over USB with
`xcrun devicectl device copy from …`. All runs on the author's own device.

## Headline numbers

| mode | measured | outcome |
|---|---|---|
| **Enumerate** | **1430** service instances / **343** unique classes; 8 denylist-skipped | 0 crashes |
| **Open** | **108** openable (class×type) across **18** classes | 0 crashes |
| **Call** (blind, all 18, `only_class=*`) | **3.45M** calls | **0 crashes, 0 hangs** |
| SigProbe | shapes swept per selector | only getters found |
| Content (shaped) | `AppleM2ScalerCSCDriver` sel 11: **2.99M** calls | 0 crashes; getter (ignores input) |

Call-phase breakdown: **3.08M / 3.45M (≈89%)** returned `kIOReturnBadArgument` — i.e. they bounced
off the `IOUserClient::externalMethod` `scalarInputCount`/`structInputSize` **gate** *before*
reaching any driver code. That gate is why blind black-box fuzzing is low-yield here.

High-value openable classes seen: `AGXAcceleratorG17P`, `AppleJPEGDriver`, `AppleM2ScalerCSCDriver`,
`AppleCLCD2`, `IOSurfaceRoot`, `H1xANELoadBalancer`, `AppleKeyStore`.

## Why "road blocked" for blind fuzzing

- The arg-shape gate rejects ~89% of calls pre-parse → they never reach driver logic.
- `SigProbe` (sweep shapes with empty content, keep the ones that return success) only finds
  **getters** — methods that succeed on empty input precisely because they don't parse it. Example
  proven: `AppleM2ScalerCSCDriver` sel 11 returned a fixed 664-byte output **regardless of input**
  across 2.99M content-fuzzed calls → it's a getter, a dead end.
- The input-*parsing* methods (where bugs live) return `kIOReturnBadArgument` on the wrong shape,
  indistinguishable from the gate → dynamic probing can't discover their shapes. You need the
  **static** dispatch table.

## The useful artifact — static `IOExternalMethodDispatch` tables

Recovered from the 27.0.1 kernelcache (`ipsw kernel extract` + `__DATA_CONST.__const` byte-scan +
dispatcher disasm; chained-fixup decode `vaddr = 0xfffffff007004000 + (raw & 0xffffffff)`), giving
the exact `(scalarCount, structSize)` of the real parse surface:

- **IOSurfaceRoot** (`IOSurfaceRootUserClient`, IOUserClient2022, 60 selectors, table A
  `@0xfffffff00831db30`, stride 40). Variable-struct input (the real fuzz surface):
  sel 0/9/10/11/19/24/26/46/47/48/50/54; fixed: 27(160B), 6(32B), 17/18(24B), 2/3(12B). A 2nd
  restricted table `@0x831e490` is gated by `[this+0x127] & 1`.
- **AppleJPEGDriver** (IOUserClient2022, 10 sel `@0x807d7d0`): sel 1/3 = (0, 88); 4/5 = (0, 4096);
  6/7 = (0, 3488); 8 = (0, 4); rest getters.
- **AppleM2ScalerCSCDriver** (classic, 12 sel): all `scalarIn=0`, flags ScalarI/ScalarO, **no struct
  input** → confirmed getter-class, no parse surface.
- **AppleSEPKeyStore**: switch-based `externalMethod`, no static table; dynamic ground-truth
  sel 0/1/16/54 only (most selectors entitlement-gated, rejected pre-parse from the sandbox).
- **AGXG17P**: ~21 sel `@0x7eb2e38`, handlers self-validate; skipped (GPU, high blast-radius).

**Key lesson (measured, not asserted):** `SigProbe` missed IOSurface/JPEG because their handlers
return `kIOReturnBadArgument` on zero content (indistinguishable from the gate) — the static table
was essential to even *find* the parse surface. Content-fuzzing those shapes is the legitimate
high-value next step; it is also why the honest expectation is low (IOSurface/JPEG are heavily
audited).

## Reproducibility notes

- `calls.jsonl` grows fast (2.27 GB in one run) → always **stream-parse**, never load whole; filter
  `"input_category":"content"` to isolate a content run.
- Every call is seeded + logged (`seed` in `fuzz_config_t`), so any interesting call replays
  deterministically.
- A run's `(class,type,selector)` + return code + timing are the measured values; 0 non-gate,
  non-getter successes were observed across all runs → the honest verdict is **hardened**.
