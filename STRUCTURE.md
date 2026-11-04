# Repository structure & conventions

This repo is organized to **scale across iOS versions** without turning into a pile of loose files.
Read this before adding a new version or area.

## Top level

```
README.md            Project overview, purpose, ethics/scope, TL;DR.
STATUS.md            The honest map: done · open questions · not-yet-reached. Update every session.
STRUCTURE.md         This file.
methodology/         Version-AGNOSTIC: tooling, the patch-diff pipeline (+ scripts), proof criteria,
                     and verification-guide.md (reproduce any claim from a public IPSW).
common/              Version-AGNOSTIC reference: glossary, shared tables.
<version>/           One folder per iOS build studied: 27.0.1/, 27.2/, 27.3/, and future 27.x/, 28.x/ …
                     (27.2/ and 27.3/ are concise landing pages; their findings live in diffs/.)
diffs/               Cross-version analysis. diffs/README.md = 3-way overview; diffs/evidence/ =
  <from>-to-<to>/    cross-version receipts; diffs/<from>-to-<to>/ = per-step patch-diffs.
assets/              Images/diagrams referenced by the docs.
```

## Inside a `<version>/<area>/` folder

Every area (sptm, txm, exclaves, kernel-zone, iokit-fuzzing, media-parsers, …) uses the **same
four sub-folders** so the layout is predictable as versions pile up:

```
<version>/<area>/
  README.md        Index + summary for this area in this version. Start here; links into reports/.
  reports/         The detailed write-ups (one file per sub-topic).
  evidence/        The receipts: disassembly excerpts, address tables, hex dumps, decompiled snippets.
                   Everything a reader needs to re-verify a claim without re-doing the RE.
  code/            Code artifacts: harnesses, analysis scripts, API contracts, PoC-for-analysis.
  experiments/     Run logs, result tables, measured values (fuzzing counts, timings, outcomes).
```

Not every area needs all four — create `code/` / `experiments/` only when there is something to
put there. `README.md`, `reports/`, and `evidence/` are the usual minimum.

## Adding a new version

1. `cp -r _TEMPLATE 27.x` (or copy an existing version's empty skeleton).
2. For each area you studied, fill `README.md` (summary) → `reports/` (detail) → `evidence/` (receipts).
3. If you diffed it against another build, add `diffs/<from>-to-<to>/`.
4. Update the root `STATUS.md` (done / open / not-yet) and the root `README.md` index.

## Writing conventions

- **Every claim is falsifiable.** A report states the mechanism, then points at the `evidence/`
  (an address, a disasm excerpt, a measured number) that proves it. No hand-waving.
- **The `evidence/<slug>.md` convention is populated** — per-build receipts under
  `<version>/<area>/evidence/` (e.g. `27.0.1/kernel-zone/evidence/proc-task-accessor.md`) and
  cross-version receipts under `diffs/evidence/` (sizes, version tags, DeviceTree grep, disasm).
  Each receipt = **Claim → Reproduction (exact command) → pulled output → annotation**. The how-to is
  [`methodology/verification-guide.md`](methodology/verification-guide.md).
- **Two outcomes, both documented honestly** (see
  [`methodology/proof-methodology.md`](methodology/proof-methodology.md)):
  - **"road blocked" / hardened** — *how we proved a path is not exploitable* (the guards, the
    exhaustive check, the mitigation that holds).
  - **"success" / real finding** — *how we proved a bug/behaviour is real* (before→after, the
    reachable input, the variant hunt).
- **Addresses are unslid** kernel/monitor VAs for the stated build; note the build in each report.
- **No firmware or binaries in git** (see `.gitignore`) — only documentation and small text
  artifacts (scripts, API headers, disasm excerpts).
