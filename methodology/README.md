# Methodology & toolchain

How every result in this repo was produced. All of it is **static** analysis of firmware plus,
where noted, read-only observation on the author's own device.

## 1. Getting the binaries

Apple ships most of the interesting components inside the IPSW, not inside the dyld_shared_cache
or kernelcache:

```sh
# whole restore image
# iPhone17,2_27.0.1_24A446_Restore.ipsw  (and 27.0, 27.2)

# kernelcache + dyld_shared_cache (arm64e)
ipsw extract --kernel --dyld <ipsw>

# the monitors and the exclave world are separate img4 payloads:
#   Firmware/sptm.t8140.release.im4p
#   Firmware/txm.iphoneos.release.im4p
#   Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p
unzip -j <ipsw> 'Firmware/sptm.t8140.release.im4p'
ipsw img4 im4p extract sptm.t8140.release.im4p        # → raw arm64e Mach-O (stripped)

# exclave bundle → its component Mach-Os
ipsw fw exclave -i <exclavecore_bundle.im4p>          # bundle/compartment map
ipsw fw exclave -o out/ <exclavecore_bundle.im4p>     # kernel/roottask/pmm/sharedcache
```

Tools used: [`blacktop/ipsw`](https://github.com/blacktop/ipsw) (v3.1.x), Ghidra 12.1.4 headless,
and a local MCP RE helper for per-function work.

## 2. Decompiling stripped binaries

The monitors, the exclave kernel, pmm, and the service cache are all **symbol-stripped**. Two
anchors make them tractable:

- **Assertion `__func__` / `file:line` strings.** Even stripped C keeps `assert`/panic strings
  that name the function and source file. `string-xref` from those recovers function identity.
- **Compiler-emitted type/field metadata.** Swift binaries keep `__swift5_*` reflection; C++ keeps
  demangled `__PRETTY_FUNCTION__` strings and RTTI — both recover type and function names.

Full all-function decompile (Ghidra headless), reused across the project:

```sh
analyzeHeadless <proj> iosRE -import <bin> -processor AARCH64:LE:64:AppleSilicon \
  -postScript ExportREInfo.java funcs.tsv parsers.txt \
  -postScript DumpAllDecomp.java decomp.c
```

Gotchas learned:
- The exclave **`ipsw fw exclave`** reconstruction of the *cL4 kernel* Mach-O emits the boot
  manifest, not the code. The real code must be **carved from the decompressed bundle**
  (`ipsw img4 im4p extract … -o raw_bundle.bin`) and loaded into Ghidra as a **raw binary**
  (`-loader BinaryLoader -loader-baseAddr 0xfffffc0000000000`).
- A shared Ghidra project imports by basename → copy each version's binary to a **unique name**
  before importing, or the second import fails "conflicting program file".
- `ipsw macho disass -x __TEXT.__text` can hang rebuilding the symbol cache on a large (22 MB)
  binary → use `--quiet` for bulk disassembly; the named cache (`.a2s`) is reused afterwards.
- A kernelcache is a **fileset**; disassemble inside it with `-t com.apple.kernel`.

## 3. Function-body patch-diff (27.0.1 → 27.2)

The "which function changed, and how" pipeline — this is what finds the silently-patched bugs:

1. Disassemble each version's `__TEXT.__text` (`ipsw macho disass -x … -q`).
2. Segment into functions by `function_starts` (or, when absent, by the `@ 0x…` markers in the
   Ghidra decompile).
3. **Normalize** each function body: strip absolute addresses / rebase-relative operands so only
   the *logic* remains.
4. Align the two function lists with a `SequenceMatcher` over normalized body hashes (handles
   inserted/removed functions without drifting), then score each changed pair by similarity.
5. Rank by **lowest similarity first** = most-changed = best bug candidate; read those.
6. For a confirmed fix, produce the before/after and a **variant hunt**: scan every sibling of the
   fixed function for the same pattern (e.g. a 32-bit `mul` feeding an allocation).

Complementary high-signal shortcut: a **string-table diff** between versions (added/removed
strings). A new `VIOLATION_*` / panic string almost always pin-points a security fix; a fix with
*no* new string is a silent in-place patch that only the body-diff catches.

## 4. Threat models used

- **Media / zero-click parsers:** attacker controls a file (image / 3D model / video) that is
  auto-decoded (Messages, Safari, QuickLook, Photos). Bug class: int-overflow→alloc, OOB r/w.
- **SPTM / TXM monitors:** attacker is a *fully compromised XNU kernel* (GL1) invoking monitor
  endpoints. Bug class: missing bound / type-confusion / TOCTOU in the monitor.
- **Exclave kernel / services:** attacker is a *compromised exclave task* (one hop past XNU), or
  XNU feeding a Tightbeam request / shared-memory. Bug class: capability confusion, parser OOB.
- **Kernel zone mitigations:** attacker already holds a kernel R/W primitive; question is what the
  mitigations still deny (type confusion, credential overwrite).

## 5. Environment

Heavy decompile/fuzzing runs on a dedicated Linux research server; per-function RE and the on-device
steps on the author's macOS + research iPhones. Risky on-device work is kept off any device that
holds irreplaceable data, and is confined to secondary/backed-up units.
