# Exclaves — 27.3 delta (vs 27.0.1 / 27.2)

This note records what changed in the `exclavecore_bundle` from 27.2 to 27.3, and re-confirms that
the 27.0.1 exclave findings (see [`../../27.0.1/exclaves/`](../../27.0.1/exclaves/)) still hold in
27.3. Short version: **the growth is Swift service churn; the cL4 micro-kernel's security-relevant
code is byte-identical to 27.0.1, so the flagship VA-capability + PAN result and the Invoke
type-bound observation carry forward unchanged.**

- Binaries on kd-app: `/root/ios-research/analysis/exclaves/273/` (bundle `exclavecore_bundle...im4p`,
  decompressed `...payload`, and extracted compartments under `ex/`). Compared against `2701/` and
  `272/`.

## Bundle size delta

| boundary | im4p bytes | delta |
|---|---|---|
| 27.0.1 | 32,325,866 | — |
| 27.2 | 32,555,242 | +229,376 (+224 KB) |
| 27.3 | 32,981,226 | **+425,984 (+416 KB)** vs 27.2 |

Per-compartment, 27.0.1 → 27.3 (extracted sizes):

| compartment | 27.0.1 | 27.3 | delta |
|---|---|---|---|
| `APP/sharedcache` (Swift+C++ services) | 22,528,000 | 23,035,904 | **+507,904 (+496 KB)** |
| `APP/roottask.brkr_artifact` | 1,706,262 | 1,827,316 | +121,054 |
| `APP/roottask` (Swift) | 7,241,728 | 7,274,496 | +32,768 |
| `APP/pmm_exclave` (C) | 589,824 | 589,824 | 0 (same size, content changed in place) |
| `SYSTEM/kernel` (manifest Mach-O) | 245,760 | 245,760 | 0 size; differs — manifest/sig noise, not carved code |

The +416 KB from 27.2→27.3 is dominated by the Swift service cache (`sharedcache`) and the broker
artifact — i.e. service-layer churn, not kernel growth.

## cL4 micro-kernel: security-relevant code is byte-identical

The real cL4 code was carved identically from each build's decompressed bundle (it occupies the
first `0x18000` bytes; the carve method is validated in
[`evidence/cl4-kernel-delta.md`](evidence/cl4-kernel-delta.md)). The carved code regions differ by
only:

- **27.0.1 → 27.2:** 49 bytes.
- **27.0.1 → 27.3:** 354 bytes (0.36%), in 14 small clusters.

All clusters fall in the **early-boot header / vector / CPU-and-GXF register-init region**
(`0x90–0x352`, a 396-byte init block at `0x17d0`, and a few scattered constants at `0xc2ad` /
`0x14646`). **None** touches the syscall dispatcher, the capability dereference, the Invoke dispatch,
or the SCTLR setup. Re-running the finding-#1 checks directly on the 27.3 carve:

- `SCTLR_EL1 = 0x3454DD9D` built at the same `0x7afc/0x7b00` (bit 23 SPAN = 0 ⇒ PAN armed) — identical.
- Whole-kernel negative controls: `msr pan` = 0, `ldtr` = 0, `sttr` = 0, `at s1e0` = 0 — still all zero.
- Cap deref `and x9,x20,#0xfffffffc0 / ldr x8,[x9] / lsr x8,#58` at `0x8470/0x8490/0x8494` — identical bytes.
- Invoke `ldr x8,[x0]; lsr #58; umull x8,w8,#0x58; ... blr x8` at `0x85ec–0x8610`, still with no type
  bound — identical bytes.

So the architectural keystone (capabilities named by VA, kept safe by PAN) and the precondition-gated
Invoke type-bound gap are **unchanged in 27.3**. The pmm C boundary changed in place but at the same
589,824 bytes (the 27.0.1→27.2 fault-handler/delta-page refactor documented in
[`../../27.0.1/exclaves/reports/pmm.md`](../../27.0.1/exclaves/reports/pmm.md) continues); the
XNU-reachable bounds themselves are unaffected by a size-neutral refactor.

## Verdict

27.3 is a service-layer refresh. The exclave TCB (cL4) is effectively frozen — its
security-relevant code is byte-for-byte what 27.0.1 shipped — so no re-audit of the kernel findings
is warranted beyond the automated re-confirmation above. The Swift/C++ service growth
(`sharedcache` +496 KB) is the only surface that would merit a fresh pass if a specific service
becomes interesting.

## Evidence

- [`evidence/cl4-kernel-delta.md`](evidence/cl4-kernel-delta.md) — carve method for 27.3, the exact
  byte-diff clusters, and the re-run of the finding-#1 invariants on the 27.3 carve.
