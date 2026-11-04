# Patch-diff scripts

The normalized function-body diff pipeline used to locate silently-patched bugs between two iOS
builds. These are the "how we proved success" tooling referenced in
[`../proof-methodology.md`](../proof-methodology.md).

## The idea

Two builds of the same binary differ mostly in *layout* (addresses shift, GOT/selector pointers
move) even when the *logic* is identical. A naive byte diff is useless. The trick is to **normalize
away layout while keeping semantic immediates** — because the security-relevant change is almost
always a changed *constant* (a size, a bound, an added overflow check), not a moved address.

Pipeline:

1. Disassemble each version's text: `ipsw macho disass <bin> -x __TEXT.__text -q` → `<v>.qasm`.
2. Get function boundaries: `function_starts` (`ipsw macho info -f`), or — when a stripped binary
   has none — the `@ 0x…` markers from the Ghidra decompile.
3. Segment instructions into functions; normalize each body (`norm_body` in `fdiff.py`, summarized
   in [`fdiff-normalization.md`](fdiff-normalization.md)): drop the address + raw-byte columns, mask
   branch/`adr`/`adrp` targets and adrp-paired pointer immediates, **keep** struct offsets and
   length/size/count constants.
4. Align the two function lists with a `SequenceMatcher` over body hashes so inserted/removed
   functions don't drift the alignment (`kextalign_sm.py`).
5. Score each changed pair by similarity; **read lowest-similarity first** (= most changed = best
   candidate).

A complementary **string-table diff** (added/removed strings between builds) is the fastest
first-pass locator: a new `VIOLATION_*`/panic string usually pin-points a fix; a fix with *no* new
string is a silent in-place patch that only the body-diff catches.

## Files

- [`norm.py`](norm.py) — standalone line normalizer (the minimal version of the idea).
- [`kextalign_sm.py`](kextalign_sm.py) — content-anchored alignment + similarity ranking (the driver).
- [`fdiff-normalization.md`](fdiff-normalization.md) — the full `norm_body` normalization rules.

> Paths in the driver are placeholders (`<TEXTDUMP>`); point them at your own `<label>_{a,b}.qasm` /
> `.starts` dumps. The scripts are deliberately tool-light (stdlib `difflib`/`hashlib`) so they run
> anywhere.
