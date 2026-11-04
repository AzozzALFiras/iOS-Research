# STATUS — where this research got to

An honest map: what is **done**, what is **open**, and what is **not yet reached**. Updated as the
work progresses. Dates are absolute.

---

## ✅ Done (with write-ups in this repo)

### Media parsers — 27.0.1 → 27.2 patch-diff (all confirmed-patched)
Full methodology demonstrated end-to-end on real current iOS. Each is an integer-overflow /
OOB in a zero-click decode path, fixed in 27.2, with before/after evidence. Every variant hunt
was negative (no unpatched sibling).

| Component | Bug (27.0.1) | Fix (27.2) | ~CVE |
|---|---|---|---|
| ImageIO `TIFFReadPlugin::decodeTileChunky` | 3-factor 32-bit mul → undersized heap buf → OOB write (TIFF/EXIF thumbnail) | widen to 64-bit + high-word guard | 112488 |
| Model I/O / USD `adobe::usd::Image::allocate` | w·h·c 3-factor 32-bit int-overflow → heap OOB write (USDZ/QuickLook) | umull + 64-bit bound + neg-check | 112565/112449 |
| USD `SdfZipFile::Iterator::operator++` | USDZ zip walk w/o local-header sig check → OOB read | add `PK\x03\x04` sig check | 112413 |
| USD `HdMeshUtil::_CountTriangles` | 32-bit tri-count accumulator → undersized alloc → OOB index write | widen to size_t + bail guards | 112461/112486 |
| USD Ptex `Block::SetSize` | log2 dims unbounded → 16-bit field overflow → mipmap heap overflow | clamp log2 < 16 | — |
| CoreMedia `_hevcbridgeParseVDRRPUDataPayload` | Dolby-Vision RPU `ue(v)` selector unclamped → downstream OOB | clamp field to [0,2] | 112688 |
| CoreGraphics `CGPDFShadingType5Init` | DeviceN numComponents > 4 → fixed inline array OOB write | bound ≤ 4 | 112611/112610 |
| Kernel IOSurface | register-after-teardown → dangling client in notify list → UAF | reject torn-down client (+0xf1 flag) | one of 112517/516/514… |
| Kernel IOHIDFamily | missing count check before indexed array access → OOB r/w | add `cmp idx,count; b.ge bail` | ~112507 |

**Lesson:** the current media surface (ImageIO/CoreMedia/ModelIO) is saturated — top researchers
(GPZ/j00ru) comb it. Patch-diff→variant-hunt here is excellent methodology practice and portfolio
proof, but low yield for a *reportable* 0-day. See [`diffs/`](diffs/) and
[`27.0.1/media-parsers/`](27.0.1/media-parsers/).

### SPTM — Secure Page Table Monitor (27.0.1)
- Architecture + GL0/1/2 model + dispatch state machine + Frame Table + retype lattice fully
  reconstructed from the stripped monitor binary (string-xref technique).
- Six 27.0.1→27.2 hardening changes located and severity-ranked; independently re-verified.
- **Verdict:** only the **T8110 DART unganged-GAPF race (§2)** holds up as a real GL1-runtime bug
  — and it is already fixed in 27.2. The GMMU-TLBI verification fix (§3/§6) is **DeviceTree-gated
  OFF** on this device (`verify-gmmu-tlbis-at-sync` absent) ⇒ the underlying race is technically
  live on 27.2 too, but there is **public prior art** → not bounty-novel. The rest are
  defense-in-depth or boot-time. See [`27.0.1/sptm/`](27.0.1/sptm/).

### TXM — Code-Signing Monitor (27.0.1)
- First full characterization + diff. Built with `-fbounds-safety` (classic OOB = trap, not
  corruption) → hunted logic/trust bugs instead. The W^X / code-signing page-authorization chain
  was cold-audited end-to-end and found **sound** (fail-closed page-type model; an uncovered-tail
  code-exec bypass was investigated and **refuted**). No confirmed bug. See
  [`27.0.1/txm/`](27.0.1/txm/).

### Exclaves — Secure-Kernel (cL4) world (27.0.1) — first teardown in this project
- Opened `exclavecore_bundle` (32 MB) → 5 arm64e Mach-Os (cL4 kernel, roottask, pmm, sharedcache
  services, brkr). Mapped the whole XNU↔exclave boundary (XnuProxy / Tightbeam IPC).
- **pmm** (physical-memory manager, C): every XNU-controlled value bound-checked → hardened.
- **cL4 micro-kernel**: syscall dispatch reconstructed; retype / IPC / CNode indexing / shifts all
  guarded. **Keystone finding:** capabilities are addressed by a *raw caller pointer* (no CNode
  radix walk, no software bound) and kept safe **only by PAN** (SCTLR.SPAN=0 arms PAN on every
  exception; EL0-writable ⟺ AP[1]=1 ⟺ PAN-blocks the kernel's load; the two forgery conditions are
  mutually exclusive). Verified: 0 `msr pan` / `ldtr` / `sttr` anywhere in the kernel.
- **EXSurface** (Swift service): pervasive Swift checked arithmetic (overflow traps + array
  bounds); no raw unchecked multiply → safe.
- **ANE ZinRt deserializer** (C++, a Mach-O-like compute-program parser — the one memory-unsafe
  service): uses widening `umull` + a `CheckRuntimeDataAccess` discipline + a `ValidHeader` gate
  (magic / 8-byte align / min-size / count ≤ 0x100) → hardened.
- **Verdict:** all four surfaces hardened; no exploitable bug. See [`27.0.1/exclaves/`](27.0.1/exclaves/).

### Kernel zone-pointer validation & the post-R/W trust boundary (27.0.1)
- `proc_task` zone layout confirmed (`task = proc + 0x768`, element `0xe38`, zone-id `0x1a`),
  cross-checked against the public Chollima/Calif.io jailbreak demo leak.
- `zone_require` / `zone_id_require` (165 sites) fully RE'd. **Trust boundary:** the anchor
  (metadata base ptr + range) is CTRR-D locked by SPTM = immutable even under kernel R/W; but the
  metadata *array* is ordinary writable memory → zone-id is **forgeable under full kernel R/W**.
- The real post-R/W wall = **RO (`ZC_READONLY`) zones** (proc_ro, ucred, cs_blob), immutable under
  **data-only** R/W (writes funnel through an SPRR-flipping pmap worker; RO in the normal domain).
- **SPRR-config question resolved:** the RO wall is a *data-only* boundary, not a *code-exec* one —
  `sprr_pperm_el1` is EL1-writable (30 sites, no GXF gate), so EL1 code-exec flips RO→RW in 3
  instructions. The real credential wall therefore = **prevent EL1 code-exec** = PAC + CTRR-A/B +
  SPTM. See [`27.0.1/kernel-zone/`](27.0.1/kernel-zone/).

### On-device IOKit fuzzing (Phase 0–2)
- Built a sandbox IOKit enumerator/fuzzer with safety layers (adaptive blocklist, circuit breaker,
  thermal guard). Ran enumerate/open/call/sigprobe/content on-device.
- **Result (honest):** 1430 service instances / 343 classes; 108 openable; 3.45M calls → **0
  crashes**. Blind black-box IOKit fuzzing from the sandbox is low-yield on hardened 27.0.1; the
  arg-shape gate + getters dominate. Recovered static dispatch tables for the real parse surface.
  See [`27.0.1/iokit-fuzzing/`](27.0.1/iokit-fuzzing/).

### Three-version trajectory — 27.0.1 → 27.2 → 27.3 beta
Full 3-way diff with reproducible evidence: [`diffs/`](diffs/). Builds iPhone17,2 24A446 → 24B119 →
24C5037i. Measured (receipts in [`diffs/evidence/`](diffs/evidence/)): SPTM `820.0.22 → 820.40.24 →
820.60.12`; TXM byte-identical (`txm-374`, 557,088 B) throughout; exclave bundle 32,325,632 →
32,555,008 → 32,980,992 B (+224 KiB, then +416 KiB); kernelcache 77,987,840 → 78,315,520 →
79,364,096 B.

- **27.0.1 → 27.2** = media memory-safety fixes + SPTM §F5 DART-race fix + §F2 `iommu_read_refcnt`
  consistency panic **added** + §F1/§F6 GMMU-TLBI verify block **added-but-DeviceTree-gated-off**.
- **27.2 → 27.3β** = SPTM new boot-time `REMAP_REGION_RNX` endpoint (strings 0/0/3) + PAPT refactor;
  services churn; **no** new security fix to any tracked surface (SPTM/TXM/exclaves/media/tracked
  kexts). Media/CoreGraphics/CoreMedia/USD: feature + recompile only, 27.2 fixes intact.
- **Persistence (live across all three):** the GMMU-TLBI DeviceTree key `verify-gmmu-tlbis-at-sync`
  is **absent on d94ap in ALL THREE** (count 0/0/0; sibling keys present) ⇒ SPTM's GMMU-TLBI verify
  is inert on this device throughout — defense-in-depth gap with public prior art, **not** bounty-novel.
  SPRR `sprr_pperm_el1` still EL1-writable (plain `msr`, no GXF gate) in 27.3β ⇒ RO wall is a
  data-only boundary in all three. proc_task layout / zone-id `0x1a` stable (27.3 address shift only).

### 27.0.1 deep re-verification — the 8-agent fan-out (2026-11-04)
Independent re-audit of every 27.0.1 surface. **All verdicts: hardened / benign / defense-in-depth.**
- **SPTM §F2** (`iommu_read_refcnt` invariant) = **defense-in-depth** (adds a consistency panic;
  desync reachability unproven — accounting code byte-identical across versions).
- **SPTM retype / type-class `0x0b` accessor churn** = **benign** (codegen, no new validation).
- **Exclaves**: cL4 capability model safe by **PAN** (0 PAN-bypass ops kernel-wide); **pmm**, Swift
  **EXSurface**, C++ **ANE ZinRt** deserializer all hardened.
- **Kernel-zone**: RO-wall **write-side** (SPRR flip), **content** (RO-element forgery), and
  **reader-side** all re-examined — hardened, with **one residual data-only lead** (below).
- **IOKit**: user-client wrapper + worker paths hardened; **media parsers** saturated/patched.
- **Correction:** `zalloc_ro_mut` is at unslid **`0xfffffff00ac482b8`** (supersedes the
  `0xfffffff00b4112cc` cited in `27.0.1/kernel-zone/reports/trust-boundary.md` — that report is owned
  by another track; the authoritative address for the RO-mutation entry is the value here).

---

## ❓ Open questions (investigated, not fully closed)

0. **THE open data-only lead — `fg_cred` / `so_cred` reader-side.** After the 8-agent fan-out, the
   single residual not-closed lead is the **reader-side** handling of file-/socket credentials
   (`fg_cred`/`so_cred`): whether a data-only R/W can influence a credential *read* path (as opposed
   to the RO-zone *write* wall, which holds). Not a confirmed bug — the one honest place a data-only
   primitive might still reach. Everything else on the kernel-zone surface is hardened.
0b. **AGXG17P GPU channel-index OOB read** (surfaced by the 27.2→27.3 kext diff) — a real OOB read
   **live in 27.2 and 27.0.1**, fixed only in 27.3 beta. Severity hinges on **reachability**: likely
   an entitlement-gated GPU-profiling path, and PAC-vtable (`blraa`) dispatch hid the `IOUserClient` +
   selector. Needs vtable/class recovery + a dynamic reachability test from an unprivileged sandbox.
   Classified "confirmed OOB read, reachability pending". See
   [`diffs/27.2-to-27.3/`](diffs/27.2-to-27.3/).
1. **SPTM GMMU-TLBI race (§F1/§F6)** — DeviceTree-gated-off on d94ap across **all three** builds
   (`verify-gmmu-tlbis-at-sync` absent, confirmed 0/0/0), so the verify is inert here; but the exploit
   (stale GPU translation → DMA to a repurposed page) is *inferred*, not dynamically confirmed, and
   has public prior art. Needs Corellium / on-HW timing to confirm. Defense-in-depth, not bounty-novel.
2. **SPTM IOMMU read-refcount invariant (§1)** — 27.2 adds a consistency panic; we could not prove
   the desync is reachable from unchanged accounting code. Likely needs dynamic testing.
3. **Kernel-zone exploitation path** — does a *practical PAC-defeating call-primitive* to
   `zalloc_ro_mut` exist (dst = a legit RO element you own + forged src)? That is the subtler path
   to cross the RO wall without full code-exec. Not resolved.
4. **ANE deserializer, one low-confidence site** (`0x83df14c`): a `[sp+0x48] × 0x838` multiply we
   could not statically tie to the preceding bound check — almost certainly a validated loop index,
   but not 100% closed.
5. **TXM recursive digest refactor** — a staging/accumulator rework in 27.2 with zero new semantic
   strings; classified refactor, reachability of the digest with attacker-controlled count unproven.

## 🚧 Not yet reached

- **Dynamic confirmation** of any SPTM/kernel inference — requires Corellium or an on-device
  harness; all monitor work here is static.
- ~~**27.2 diff of the zone-metadata submap / SPRR config**~~ — **answered (No, through 27.3β).**
  The SPRR RO-zone worker still flips `sprr_pperm_el1` with a plain EL1 `msr` (no GL/GXF trap) and the
  zone anchors are still `__DATA_CONST` r--, byte-identical idiom in 27.2 and 27.3 beta. The walls
  remain **data-only** boundaries. Receipt: [`diffs/evidence/sprr-ro-wall.md`](diffs/evidence/sprr-ro-wall.md).
- **Other exclave services** — XnuSharedSegment mapping, SharedDARTMapperService, securepairingd /
  corespeechd / the rest of the conclaves, roottask (7 MB Swift). Diminishing returns expected.
- **Remaining ImageIO decoders** with 27.2 CVEs not yet mapped (PSD / KTX / KTX2 / BC).
- **Kernelcache UAF/type-confusion CVEs** (the highest-bounty class) beyond IOSurface/IOHID — needs
  lifetime analysis, not body-diff.
- **A fresh (unpatched) bug** on any surface — none found; this remains the open-ended, hard goal.

---

## Methodology note

The consistent outcome — "hardened, already-patched, or by-design" — is the honest signal that
current iOS is comprehensively defended, and that patch-diff + variant-hunting on well-combed
surfaces is high-skill but low-yield for novel bugs. The durable value here is the **reconstructed
architecture and trust boundaries**, which this repo documents so the next person (including future
me) does not have to re-derive them.
