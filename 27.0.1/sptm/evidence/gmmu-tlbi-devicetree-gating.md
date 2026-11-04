# Evidence — GMMU-TLBI verify is DeviceTree-gated OFF across all three builds

**Claim.** The 27.2 GPU-MMU TLBI *completion-verify* block (finding §F1/§F6) is wrapped in a flag
set only from the DeviceTree key **`verify-gmmu-tlbis-at-sync`**. That key has **0 occurrences** on
iPhone17,2 / `d94ap` in **27.0.1, 27.2 AND 27.3**, while **`issue-gmmu-tlbis-at-retype` = 1** in all
three. So on this device the TLBI is still *issued* but the 27.2 verify block is **inert** — the
"fix" never runs here, and the behaviour is identical across the three builds.

DeviceTrees: `DeviceTree.d94ap.im4p` extracted from each `iPhone17,2_*_Restore.ipsw`.

## Reproduce

Extract the (LZSS/LZFSE-compressed) DeviceTree payload from each IPSW, then grep the decompressed
blob. The `im4p extract` step is required — grepping the raw `.im4p` finds nothing because the
payload is compressed.

```
# per version V in {27.0.1, 27.2, 27.3}:
ipsw img4 im4p extract --output /tmp/dt_$V.out \
  /root/ios-research/_evidence/$V/Firmware/all_flash/DeviceTree.d94ap.im4p

strings /tmp/dt_$V.out | grep -c 'verify-gmmu-tlbis-at-sync'
strings /tmp/dt_$V.out | grep -c 'issue-gmmu-tlbis-at-retype'
strings /tmp/dt_$V.out | grep -iE 'gmmu.?tlbi' | sort -u
```

(The IPSW path for the extract source is
`/root/ios-research/firmware/iPhone17,2_<ver>_<build>_Restore.ipsw` →
`Firmware/all_flash/DeviceTree.d94ap.im4p`; the pre-extracted copies live under
`/root/ios-research/_evidence/<ver>/`.)

## Output (real)

```
---------- 27.0.1 ----------
verify-gmmu-tlbis-at-sync : 0
issue-gmmu-tlbis-at-retype: 1
all gmmu-tlbi lines:
issue-gmmu-tlbis-at-retype
---------- 27.2 ----------
verify-gmmu-tlbis-at-sync : 0
issue-gmmu-tlbis-at-retype: 1
all gmmu-tlbi lines:
issue-gmmu-tlbis-at-retype
---------- 27.3 ----------
verify-gmmu-tlbis-at-sync : 0
issue-gmmu-tlbis-at-retype: 1
all gmmu-tlbi lines:
issue-gmmu-tlbis-at-retype
```

## Annotation (bytes → claim)

- `issue-gmmu-tlbis-at-retype` = 1 in all three → the GPU-MMU TLBI **is** issued on this device at
  retype, every build.
- `verify-gmmu-tlbis-at-sync` = 0 in all three → the flag that enables the 27.2 TLBI
  *completion-verify* / Dekker-lock block is **never set** on `d94ap`. The verify code is compiled in
  but gated off.
- Net: the §F1/§F6 "verify" hardening is inert on iPhone17,2 across 27.0.1 → 27.2 → 27.3. The
  underlying async-completion question is unchanged on this device in all three builds; it is a
  **dynamic** question, and there is public prior art, so it is not treated as a novel finding here.
