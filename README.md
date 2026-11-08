# iOS-Research

Static reverse-engineering notes, patch-diffs, and trust-boundary analysis of modern iOS
system security — **for learning and experimentation**.

**Author:** Azozz ALFiras · [github.com/AzozzALFiras](https://github.com/AzozzALFiras)

---

## ⚠️ Purpose & scope (please read first)

This repository is an **educational security-research notebook**. Its goal is to *understand how
modern iOS defends itself* — the monitors (SPTM/TXM), the Secure-Kernel "exclave" world, the
kernel's zone-pointer mitigations, and the media parsers — by reading the shipping firmware and
writing down, clearly, how each mechanism works and where its trust boundaries are.

- **Everything here is static analysis of publicly downloadable firmware** (Apple IPSWs) and,
  where a device is involved, of the author's **own research devices** with the owner's
  authorization. No third-party systems are touched.
- **No weaponized exploit, no 0-day, no jailbreak is published here.** Where a vulnerability is
  discussed, it is either (a) already fixed by Apple in a later release (documented as a
  patch-diff, the way public security writeups do), or (b) a *trust-boundary observation*
  (e.g. "mitigation X assumes attacker does not yet have capability Y") — not a working attack.
  The recurring result across this research is, honestly, **"hardened — no exploitable bug
  found."** That negative result is itself the point: it documents *why* current iOS is hard.
- The author does this kind of work for **responsible disclosure** (Apple Security Bounty) and
  for CV / skill development. Nothing in this repo is intended to enable harm to real users or
  real systems, and it must not be used that way.
- This is **not** affiliated with or endorsed by Apple. "iOS", "Apple Silicon", SPTM, TXM, etc.
  are Apple's.

If you are from Apple PSIRT and something here concerns you, please open an issue — happy to
adjust or take it down.

---

## Platform under study

| | |
|---|---|
| Device | iPhone 17,2 (A18 Pro-class, arm64e), DeviceTree `d94ap` |
| iOS builds | 27.0 (24A437), **27.0.1 (24A446)**, **27.2 (24B119)**, **27.3 beta (24C5037i)** |
| Primary technique | `ipsw` extraction → Ghidra headless decompile → function-body patch-diff → targeted `ipsw macho disass` / REA |
| SPTM (measured) | `820.0.22` (27.0.1) → `820.40.24` (27.2) → `820.60.12` (27.3β) |
| TXM (measured) | `txm-374`, **byte-identical** (557,088 B) across all three builds |
| Also | SK/cL4 exclave kernel; exclave bundle 32.33 → 32.56 → 32.98 MB |

**Three-version trajectory:** 27.0.1 → 27.2 = media + monitor hardening (all confirmed-patched);
27.2 → 27.3β = feature + recompile, **no** new fix to any tracked surface. The standout
live-across-all-three observation is the GMMU-TLBI DeviceTree gating gap (defense-in-depth, public
prior art). See [`diffs/`](diffs/) for the full 3-way diff with reproducible evidence.

See [`methodology/`](methodology/) for the full toolchain and the patch-diff pipeline, and
[`methodology/verification-guide.md`](methodology/verification-guide.md) to reproduce any claim.

---

## What's inside

```
STATUS.md          Where we got to · open questions · not-yet-reached — the honest map
STRUCTURE.md       Folder conventions (how this scales as more iOS versions are added)
methodology/       Tooling, the decompile+diff pipeline (+ scripts), and how we PROVE a verdict
  patch-diff-scripts/   the normalized function-body diff tooling (runnable)
  proof-methodology.md  how we prove "road blocked / hardened" vs "success / real bug"
  verification-guide.md how to reproduce ANY claim from a public IPSW (extraction + gotchas)
common/            Version-agnostic reference (glossary of SPTM/TXM/SPRR/PAN/CTRR/zone terms)
27.0.1/            The primary build studied. Each area = README (summary) + reports/ + evidence/
  sptm/            Secure Page Table Monitor: architecture + GL1 attack surface + 6 findings
  txm/             Code-Signing Monitor: W^X / code-signing enforcement audit
  exclaves/        Secure-Kernel (cL4) world: bundle teardown, pmm, kernel+PAN, EXSurface, ANE
  kernel-zone/     zone-pointer validation, proc_task layout, the post-R/W trust boundary
  iokit-fuzzing/   On-device IOKit fuzzing (code/ + experiments/), honest low-yield result
  media-parsers/   ImageIO / CMPhoto / MediaToolbox zero-click decode surface (static audit)
  krw-dead-paths/  27 tested-and-eliminated paths to kernel R/W — the map of what doesn't work
27.2/              Landing page: what changed in 27.2 (advisory mapping; findings live in diffs/)
27.3/              Landing page: 27.3 beta = feature + recompile, no new tracked-surface fix
diffs/             Cross-version analysis — START HERE for the 3-version story
  README.md             the 3-way overview + trajectory + persistence-findings table
  evidence/             reproducible receipts (sizes, version tags, DeviceTree grep, disasm)
  27.0.1-to-27.2/       function-body patch-diffs (confirmed-patched bugs, before/after)
  27.2-to-27.3/         feature release; AGXG17P GPU OOB-read fix (live in 27.2/27.0.1, reach pending)
```

New to the repo? Read `STATUS.md` (the map), then `methodology/proof-methodology.md` (how claims are
proven), then dive into any `27.0.1/<area>/`. Structure conventions for adding versions: `STRUCTURE.md`.

---

## TL;DR of the findings

A one-paragraph honest summary (full detail in [`STATUS.md`](STATUS.md)):

- **Media parsers (ImageIO/USD/CoreMedia/CoreGraphics + some kernel kexts):** several memory-safety
  bugs were precisely reverse-engineered **but all were already patched by Apple in 27.2** (clean
  patch-diffs with before/after). Every variant hunt came back negative → the current media
  surface is a saturated, well-combed target.
- **SPTM / TXM monitors:** fully mapped architecturally; six 27.0.1→27.2 hardening changes
  located. After deep reachability tracing only the T8110 DART concurrency fix held up as a real
  GL1-runtime bug (already patched); one TLB-verification fix turns out to be DeviceTree-gated-off
  on this device. No unpatched, bounty-eligible monitor bug confirmed.
- **Exclaves (first teardown in this project):** the physical-memory manager (C), the cL4
  micro-kernel, the EXSurface service (Swift) and the ANE compute-program deserializer (C++)
  were each audited — **all comprehensively hardened.** The most interesting finding is
  architectural, not a bug: the micro-kernel addresses capabilities by a raw caller pointer with
  no software bound, and is kept safe purely by **PAN** (Privileged Access Never) + the AP[1]/PAN
  mutual exclusion.
- **Kernel zone mitigations:** `zone_id_require` (165 sites) is bypassable *once you already have
  kernel R/W* (the metadata array is writable), but the real wall — read-only (`ZC_READONLY`)
  zones holding credentials — holds against **data-only** R/W. That wall is itself only a
  data-only boundary: it falls to **EL1 code-execution** (the `sprr_pperm_el1` remap is
  EL1-writable), which is in turn what PAC + CTRR + SPTM exist to prevent.
- **Kernel R/W primitive (27.0.1):** 27 distinct paths tested on device — IPC request table race
  (CVE-2026-112507: table grows once, freelist prevents race), ANE OOB (CVE-2026-84494: buffer in
  `aned` daemon, sandbox barrier), AVE/AVC encoder (VT userspace validates bounds before kernel),
  GPU/Metal (UAT isolates GPU from kernel memory), Handle Race strategies (type isolation blocks
  cross-zone spray). **All dead.** KASLR was independently defeated via a timing oracle, but the
  kR/W step remains the sole unsolved stage of the chain. The structural lesson: iOS 27's type
  isolation (`kalloc_type` per-type zones) blocks every heap-based kR/W approach; successful modern
  jailbreaks (kfd, ClearSword) work at the physical-page or VM/VFS layer. The value here is the
  exhaustive map of what doesn't work and why, so the next researcher starts from our frontier,
  not from scratch. See [`27.0.1/krw-dead-paths/`](27.0.1/krw-dead-paths/).

**Net:** current iOS (27.0.1) is hardened across every surface examined here. The value of this
repo is the *map* — the mechanisms, the trust boundaries, and the methodology — not a break.

---

## License

Documentation and original analysis © Azozz ALFiras, released for educational use
(see [`LICENSE`](LICENSE)). Firmware, symbol names, and Apple trademarks belong to Apple Inc.
