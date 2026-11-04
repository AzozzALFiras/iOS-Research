# Proof methodology — how we prove "road blocked" vs "success"

Reverse-engineering a mitigation produces one of two verdicts. Both are real results; both must be
*proven*, not asserted. This note defines the bar each must clear, so a reader can trust the
"hardened" verdicts as much as the "bug" ones. (Most of this research lands on **hardened** — that
is the honest signal that current iOS is well-defended, and documenting *why* is the point.)

---

## A. Proving the road is blocked (a path is NOT exploitable / is hardened)

A "hardened" verdict is only as good as its coverage. We accept it when **all** of these hold:

1. **The sink is identified.** Name the dangerous operation — the allocation, the `memcpy`, the
   array index, the pointer arithmetic, the capability dereference, the type decision.
2. **Every path to the sink is enumerated.** Not "the paths I happened to read" — the *transitive*
   set. Techniques used here:
   - whole-binary instruction scans (e.g. "every `mul`/`umull` in the parser region", "every
     `msr sprr_pperm_el1` in the kernel", "every variable-shift site") — a count, not a sample;
   - call-graph closure from the entry handler to the sink;
   - string/metadata-anchored function discovery so no reachable handler is missed.
3. **A dominating guard is shown for each path.** For every route to the sink, cite the check that
   must pass first — a bound (`cmp idx,count; b.hs trap`), an overflow guard (widening `umull`, or
   `adds; b.vs trap`, or a high-word `lsr #0x20; cbnz`), a type gate, or a hardware property
   (PAN/SPRR/CTRR). Give the **address** and the instruction.
4. **The guard is tied to the attacker-controlled value.** It is not enough that *a* check exists;
   it must dominate the *specific* value the attacker controls (we explicitly flag the one case we
   could not tie — ANE `0x83df14c` — rather than claim closure).
5. **Negative controls.** Where the mechanism is hardware (PAN, SPRR, CTRR), prove the escape
   hatches are absent: e.g. "0 `msr pan` / `ldtr` / `sttr` in the entire kernel" means PAN can
   never be cleared → the mutual-exclusion argument holds globally, not just locally.

A hardened verdict that cannot meet #2 or #5 is downgraded to "no bug *found*" and the residual is
written into [`../STATUS.md`](../STATUS.md) as an open question — never upgraded to "safe".

**Worked examples in this repo:**
- Exclave cL4 capabilities → [`../27.0.1/exclaves/reports/cl4-kernel-pan.md`](../27.0.1/exclaves/reports/cl4-kernel-pan.md)
  (sink = raw-pointer cap deref; guard = PAN; negative control = 0 PAN-bypass ops).
- ANE ZinRt parser → [`../27.0.1/exclaves/reports/ane-zinrt.md`](../27.0.1/exclaves/reports/ane-zinrt.md)
  (sink = count×size alloc; guard = widening `umull` + `CheckRuntimeDataAccess`; control = 191 vs 10
  multiply classification).
- Kernel RO-zone wall → [`../27.0.1/kernel-zone/reports/trust-boundary.md`](../27.0.1/kernel-zone/reports/trust-boundary.md)
  (sink = credential write; guard = SPRR; scope boundary = data-only vs code-exec, proven by the
  `sprr_pperm_el1` register being EL1-writable).

---

## B. Proving success (a bug / behaviour is real)

For a memory-safety finding we require:

1. **The reachable input.** Show the attacker-controlled value and the path from an entry point
   (a decoded file field, a Tightbeam/IOKit argument, a monitor endpoint scalar) to the sink.
2. **The defect, at instruction level.** The exact arithmetic/indexing that goes wrong — e.g. a
   *three-factor 32-bit* multiply feeding `malloc` with no widening and no high-word guard.
3. **Before → after.** For a patched bug, the 27.0.1 code and the 27.2 fix, side by side, produced
   by the normalized function-body diff (see [`patch-diff-scripts/`](patch-diff-scripts/)). The fix
   *is* the proof the bug was real: Apple added exactly the missing guard.
4. **A variant hunt.** Scan every sibling of the fixed function for the same pattern. A negative
   hunt ("all siblings use widening `umull`") bounds the finding; a positive hunt would be a new
   candidate. We report the hunt result either way.
5. **Honest reachability caveats.** If exploitability is *inferred* (e.g. a race whose window needs
   on-hardware timing, or a path gated by a DeviceTree key), say so — do not round "strongly
   supported" up to "exploitable".

**Worked examples in this repo** (all already patched by Apple — documented as learning, not
weapons): [`../diffs/27.0.1-to-27.2/media.md`](../diffs/27.0.1-to-27.2/media.md) — each entry is a
before→after with the reachable input and the variant hunt.

---

## Why so much ends in "hardened"

Across media parsers, SPTM, TXM, the exclave world, and the kernel zone mitigations, the recurring
result is *hardened / already-patched / by-design*. That is not a failure of the method — it is the
measurement: modern iOS is comprehensively defended, and the well-combed surfaces (ImageIO, etc.)
are saturated. The durable deliverable is the **map** — the mechanisms and trust boundaries proven
to the bar above — so the work is reusable rather than repeated.
