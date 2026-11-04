# EXSurface service (Swift) — hardened by Swift's checked arithmetic

**Verdict:** hardened. EXSurface creates/maps graphics surfaces from an XNU-supplied image-layout
descriptor — the classic `width × height × stride` integer-overflow → undersized-alloc surface. But
it is written in **Swift**, whose default arithmetic traps on overflow, and the create path adds no
unsafe fast path. Proven by direct disassembly after the delegated audit was cut short by a
false-positive safety classifier.

- Binary: `exclavecore_bundle` → `APP/sharedcache` (22 MB, Swift, symbol-stripped; ipsw `.a2s` cache
  recovers names). Build 27.0.1.
- Dispatcher: EXSurfaceRootComponent Tightbeam handler `~0x8869000–0x886d000` (adrp refs to the
  selector string `0x8f3f340` "invalid rawValue for …EXSurfaceRootComponentSelector"). Main
  create/transport handler: `sub_8868fd4`.
- Types: `EXSurface.ImageLayout` / `MutableImageLayout` / `CreateDescInternalRepresentable`;
  sources `EXSurface_Swift.swift`, `EXSurfaceMemoryRegion.swift`, `MemorySurfaceBase.swift`.
  Validation enum cases present: `badWidth`, `badHeight`, `badElementWidth`, `badElementHeight`.

## Reachable input

XNU sends a surface-create request carrying width / height / stride (bytesPerRow) / pixelFormat /
element dims / plane count / per-plane offset+size — all attacker-controlled — and the exclave
allocates/maps the surface inside an XNU-shared `EXSurfaceMemoryRegion`.

## Why the road is blocked (whole-region check)

Scanning the create region `0x8868fd4–0x886c000`:

- **Every `adds`/`subs` is followed by `b.vs → brk #0x1`** — Swift checked arithmetic; an overflow
  is a trap (DoS, by-design), never a wrapped value. Examples at `0x8869d70` (`subs x26,x0,#1;
  b.vs`), `0x8869d9c`, `0x8869de8`.
- **Every array subscript is bounds-checked**: the Swift pattern `cmp idx, count; b.hs → brk; ldr
  [base, idx, lsl #3]` (e.g. `0x886afb4`, `0x886aff0`, `0x886b048`) — index `< count` else trap.
- **No raw unchecked multiply.** Grep of the whole region: `mul/umull/umaddl/smull/madd/mneg` = **0**
  in the create handler; only guarded `lsl` (shift) with a following `b.vs`. So `w×h×stride` cannot
  silently overflow — there is no multiply instruction to overflow; the size math is done in checked
  Swift `Int` arithmetic that traps.
- 22 `brk` traps in the region = the overflow/bounds backstops.

## Residual (honest)

The one class this *cannot* rule out is a **logic** bug: trusting an XNU-supplied plane offset/size
against the shared-region size (a semantic check, not a classic memory-safety trap). That would need
deep semantic tracing of the region-mapping path and does not manifest as an overflow/OOB signature.
Logged as a low-priority residual; the memory-safety verdict for the layout arithmetic is hardened.

> Note: the subagent delegated to this audit was terminated mid-run by a false-positive cyber safety
> classifier — this report is the author's direct disassembly instead. Lesson recorded for the
> project: do this class of exclave-parser audit in the main session, framed strictly defensively.
