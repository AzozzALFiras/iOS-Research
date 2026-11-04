# Verification guide — reproduce any claim in this repo from scratch

Every verdict in this repo is meant to be **independently checkable**. This guide tells a reader how
to go from a public IPSW to the exact bytes a report cites, so "the analysis function" is in the repo
and you can paste a command and see the same disassembly. If you can't reproduce a claim with this
guide, treat the claim as unproven and open an issue.

The companion document [`proof-methodology.md`](proof-methodology.md) defines *what bar* a claim must
clear ("road blocked" vs "success"); this document is the *mechanical how-to* for the receipts.

---

## 1. Toolchain

| tool | version used | role |
|---|---|---|
| [`blacktop/ipsw`](https://github.com/blacktop/ipsw) | **v3.1.739** (`ipsw version`) | img4/Mach-O extraction + disassembly + a2o/a2s |
| Ghidra (headless) | 12.1.4 PUBLIC | full-binary decompile of the stripped monitors/exclave kernel |
| `strings`, `stat`, `unzip` | coreutils / binutils | version tags, sizes, DeviceTree keys |
| normalized body-diff | this repo | [`patch-diff-scripts/`](patch-diff-scripts/) (`norm.py`, `kextalign_sm.py`) |

Firmware stays off git (see `.gitignore`); it is downloaded per build. Builds studied, all
`iPhone17,2`: **27.0.1 = 24A446**, **27.2 = 24B119**, **27.3 beta = 24C5037i**.

---

## 2. Where each binary comes from (exact extraction)

Apple ships the interesting components as **separate img4 payloads** in the IPSW, not inside the
shared cache. `$IPSW` = `iPhone17,2_<ver>_<build>_Restore.ipsw`; `$V` = a per-version scratch dir.

```sh
# --- monitors + DeviceTree + exclave bundle (img4 payloads in the zip) ---
unzip -oq "$IPSW" \
  'Firmware/sptm.t8140.release.im4p' \
  'Firmware/txm.iphoneos.release.im4p' \
  'Firmware/all_flash/DeviceTree.d94ap.im4p' \
  'Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p' -d "$V"

ipsw img4 im4p extract "$V/Firmware/sptm.t8140.release.im4p"   -o "$V/sptm.bin"   # arm64e Mach-O (stripped)
ipsw img4 im4p extract "$V/Firmware/txm.iphoneos.release.im4p" -o "$V/txm.bin"
ipsw img4 im4p extract "$V/Firmware/all_flash/DeviceTree.d94ap.im4p" -o "$V/dt.bin"   # DeviceTree is an im4p
ipsw img4 im4p extract "$V/Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p" -o "$V/exclave.bin"

# --- exclave bundle → component Mach-Os (cL4 kernel / roottask / pmm / sharedcache services) ---
ipsw fw exclave -i "$V/Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p"          # bundle/compartment map
ipsw fw exclave -o "$V/exclave_out/" "$V/Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p"

# --- kernelcache (fileset) + dyld_shared_cache ---
ipsw extract --kernel --dyld "$IPSW"      # → <build>__iPhone17,2/kernelcache.release.iPhone17,2 + dyld_shared_cache_arm64e*
```

---

## 3. Gotchas that bite verifiers

These are the exact traps this project hit — skip them and you get wrong or hung results:

1. **Kernelcache is an MH_FILESET.** Disassemble *inside* the fileset entry, not the container:
   `ipsw macho disass -t com.apple.kernel …`. Without `-t com.apple.kernel` you address the wrong
   image.
2. **`ipsw macho disass -x` hangs on the 22 MB dyld_shared_cache** rebuilding the symbol cache — pass
   `--quiet` (`-q`) for bulk disassembly; the named `.a2s` cache is reused afterward.
3. **The carved cL4 kernel is a RAW blob**, not a loadable Mach-O — `ipsw fw exclave`'s kernel
   reconstruction emits the boot manifest, not the code. Carve it from the decompressed bundle and
   load at base `0xfffffc0000000000` (`llvm-objdump --adjust-vma=0xfffffc0000000000`, or Ghidra
   `-loader BinaryLoader -loader-baseAddr 0xfffffc0000000000`).
4. **IOKit dispatch handler pointers are packed**: a raw table entry decodes as the absolute VA
   `0xfffffff007004000 + (raw & 0xffffffff)` — don't read the raw 64-bit word as the pointer.
5. **DeviceTree is an im4p**, not a flat file — extract with `ipsw img4 im4p extract` before
   `strings`/grep (step 2).
6. **Shared Ghidra project imports by basename** → copy each build's binary to a unique name first
   (`sptm_2701.bin`, `sptm_272.bin`) or the second import fails "conflicting program file".
7. **Relocate by content, never by a prior build's VA.** Addresses shift every build; find a function
   by its `zone_create` immediates / panic string / cstring xref, then record the *new* VA. (This is
   why each cross-version receipt re-derives the address — see the proc_task receipt.)

---

## 4. The evidence convention

Every non-trivial claim is backed by a receipt file: for per-build work, `27.0.1/<area>/evidence/<slug>.md`;
for cross-version work, [`diffs/evidence/<slug>.md`](../diffs/evidence/). A receipt has three parts:

1. **Claim** — one or two sentences, with the unslid VA(s).
2. **Reproduction** — the exact command(s): which binary, which address/string, which flags.
3. **Disassembly / output (pulled)** — the real bytes/strings, then a short **annotation** tying the
   instructions to the claim.

So "the analysis function" lives in the repo: a reader pastes the command from part 2 and sees the
output in part 3. A report body states the mechanism and links the receipt; it never hand-waves.
(Worked per-build example already in the tree:
[`27.0.1/kernel-zone/evidence/proc-task-accessor.md`](../27.0.1/kernel-zone/evidence/proc-task-accessor.md).)

---

## 5. One fully-worked example, end to end

**Claim to verify:** SPTM's GMMU-TLBI completion-verify (added in 27.2) is **inert on iPhone17,2 in
all three builds**, because the DeviceTree key that arms it, `verify-gmmu-tlbis-at-sync`, is not
shipped for d94ap. (This is the repo's standout live-across-all-three observation.)

**Step 1 — get the DeviceTree for each build** (step 2 above):

```sh
ipsw img4 im4p extract "$V/Firmware/all_flash/DeviceTree.d94ap.im4p" -o "$V/dt.bin"
```

**Step 2 — the analysis function (grep the key, and a control):**

```sh
strings -a "$V/dt.bin" | grep -c 'verify-gmmu-tlbis-at-sync'      # is the gating key present?
strings -a "$V/dt.bin" | grep -iE 'gmmu|tlbi' | sort -u            # control: which GMMU/TLBI keys DO exist?
```

**Step 3 — output (pulled 2026-11-04):**

```
verify-gmmu-tlbis-at-sync : count=0   in 27.0.1, 27.2, AND 27.3 beta
present GMMU/TLBI keys     : issue-gmmu-tlbis-at-retype
                             tlbi-flushes-smmu
```

**Step 4 — conclusion.** `count = 0` in all three IPSWs means the flag (`DAT_…[0x81] & 1`) that gates
the verify block can never be set on this SoC, so the 27.2 "fix" never arms here — 27.2 and 27.3
behave like 27.0.1. The control grep proves this is a genuine negative, not a stripped/misparsed tree:
the GMMU/TLBI key namespace **is** present (`issue-gmmu-tlbis-at-retype`, `tlbi-flushes-smmu`); Apple
simply did not ship `verify-gmmu-tlbis-at-sync` for d94ap. Honest status: the underlying
async-completion race is a *high-confidence inference* with *public prior art*, so this is a
defense-in-depth gap, not a bounty-novel 0-day. Full receipt + the SPTM-side mechanism:
[`diffs/evidence/gmmu-tlbi-devicetree-gating.md`](../diffs/evidence/gmmu-tlbi-devicetree-gating.md)
and [`27.0.1/sptm/reports/findings.md`](../27.0.1/sptm/reports/findings.md) §F1.

> A second end-to-end disassembly example (command → `ipsw macho disass` output → conclusion) is the
> SPRR RO-zone worker: [`diffs/evidence/sprr-ro-wall.md`](../diffs/evidence/sprr-ro-wall.md). It shows
> the `msr sprr_pperm_el1` flip and proves the credential wall is a *data-only* boundary in 27.3 beta.

---

## 6. Checklist

- [ ] Correct build (`<build>__iPhone17,2`) and correct payload (§2).
- [ ] Addresses re-derived by content anchor for *this* build, not copied from another (§3.7).
- [ ] Kernelcache disassembled with `-t com.apple.kernel`; big images with `--quiet` (§3.1–3.2).
- [ ] The guard you cite dominates the *attacker-controlled* value, not just "a check exists"
      (see [`proof-methodology.md`](proof-methodology.md) §A.4).
- [ ] Verdict matches what the bytes show — hardened / patched / defense-in-depth / boot-time /
      open-lead — with reachability caveats stated, not rounded up.
</content>
