# iOS 27.0.1 (24A446) — iPhone 17,2

The primary build studied in this repo. 27.0.1 is the interesting "current" target: it predates the
media-parser fixes that landed in 27.2, and it is the build the public Chollima/Calif.io jailbreak
demo targets, so its mitigations are worth understanding in detail.

## Contents

| Area | What's there |
|---|---|
| [`sptm/`](sptm/) | Secure Page Table Monitor — architecture, GL1 attack surface, 6 hardening findings (only §2 a real GL1 bug, all patched) |
| [`txm/`](txm/) | Code-Signing Monitor — W^X / code-signing enforcement cold-audit (sound), refactor diff |
| [`exclaves/`](exclaves/) | Secure-Kernel (cL4) world — bundle teardown, pmm (C), micro-kernel + PAN, EXSurface (Swift), ANE deserializer (C++) — all hardened |
| [`kernel-zone/`](kernel-zone/) | `zone_id_require` + `proc_task` layout + the post-R/W trust boundary (RO zones, SPRR, the full chain) |
| [`iokit-fuzzing/`](iokit-fuzzing/) | On-device sandbox IOKit fuzzing, 0 crashes, static dispatch tables |
| [`media-parsers/`](media-parsers/) | Zero-click decode surface map (ImageIO/CMPhoto/MediaToolbox), hardened |

Cross-version patch-diffs (the confirmed-patched media/kernel bugs) are in
[`../diffs/`](../diffs/); the honest project map is in [`../STATUS.md`](../STATUS.md).

## The one-line summary

Every surface examined on 27.0.1 is **hardened** — the exploitable bugs that existed were all fixed
in 27.2, and the monitor/exclave/zone surfaces had no confirmed exploitable bug. The durable output
is the reconstructed architecture and, especially, the **kernel credential trust chain**
(constrained primitive → data-only R/W → RO-zone/SPRR wall → needs code-exec → PAC+CTRR+SPTM).
