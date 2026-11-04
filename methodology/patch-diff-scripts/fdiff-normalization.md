# `norm_body` — normalization rules

The heart of the patch-diff. Given the disassembled instructions of one function, produce a
canonical body that is **layout-independent but semantics-preserving**, so two builds compare equal
iff their logic is equal.

Instruction line shape (from `ipsw macho disass -x __TEXT.__text -q`):

```
0x<addr>:  <1-8 raw bytes>   <mnemonic> <operands>
```

Rules applied per instruction:

1. **Drop the address + raw-byte columns.** Pure layout; always differs.
2. **Mask branch / `adr` / `adrp` targets.** `b`, `bl`, `cbz`, `tbz`, `b.<cond>`, `adr`, `adrp`
   operands are layout-dependent → replaced with a placeholder. (Control-flow *structure* is still
   captured by the sequence of masked branches; only the absolute targets are blanked.)
3. **adrp-pair tracking.** When a register currently holds an `adrp` page value (a GOT / selector /
   cstring / data pointer base), an immediate added to it is **masked** — these are relocation
   noise. The "this register holds a page" mark propagates through `add`/`mov` and clears when the
   register is redefined. This is what stops moved global/string pointers from showing up as diffs.
4. **KEEP every other immediate.** Struct offsets (`[x8, #0x40]`), lengths, sizes, counts, shift
   amounts, comparison constants (`cmp x8, #0x100`) are **preserved verbatim**. These are exactly
   the security-relevant constants: an added bound, a changed element size, a new overflow limit.
5. Register names are kept (so data-flow shape survives); only their *values*/targets are masked
   per the rules above.

### Why this finds the bugs

Every confirmed-patched bug in this repo surfaced as a **kept-immediate change**:

- `TIFFReadPlugin::decodeTileChunky` — 27.2 inserts `lsr x8, #0x20; cbnz bail` (a new high-word
  guard) + switches a `mul` to `umull`: the new compare-constant and the mnemonic change both
  survive normalization → the pair scores low similarity → flagged.
- `CGPDFShadingType5Init` — 27.2 inserts `cmp x9, #0x4; b.hi bail`: the literal `#0x4` bound is a
  kept immediate → visible.
- `_hevcbridgeParseVDRRPUDataPayload` — 27.2 inserts `cmp w23, #0x2; b.hi`: kept `#0x2` → visible.

Conversely, a function that only moved in memory (its globals/strings relocated) normalizes to an
identical body → correctly reported **unchanged**, keeping the changed-set small and readable.

### Limitations

- Sub-instruction in-place patches that change only a masked operand are invisible (rare; caught by
  reading the few low-similarity survivors).
- Unnamed/stripped functions are matched by position+content, not name — hence the content-anchored
  `SequenceMatcher` alignment in `kextalign_sm.py`.
