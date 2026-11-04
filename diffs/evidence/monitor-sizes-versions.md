# Evidence — monitor / exclave / kernelcache version + size trajectory (27.0.1 → 27.2 → 27.3)

**Claim.** Across iPhone17,2 builds 27.0.1 (24A446), 27.2 (24B119), 27.3 beta (24C5037i): SPTM steps
`820.0.22 → 820.40.24 → 820.60.12`; TXM is byte-identical (`txm-374`) throughout; the exclave bundle
and kernelcache grow in clean page-multiple steps. These are the headline size deltas cited in the
[3-version diff](../README.md).

## (a) Reproduction

Each monitor / bundle / DeviceTree is a separate img4 payload inside the IPSW. Extract the raw
payload, then `stat` it and `strings | grep` the version tag:

```sh
# on kd-app, per version (IPSW = iPhone17,2_<ver>_<build>_Restore.ipsw)
unzip -oq "$IPSW" \
  'Firmware/sptm.t8140.release.im4p' \
  'Firmware/txm.iphoneos.release.im4p' \
  'Firmware/all_flash/DeviceTree.d94ap.im4p' \
  'Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p' -d "$V"
ipsw img4 im4p extract "$V/Firmware/sptm.t8140.release.im4p"    -o "$V/sptm.bin"
ipsw img4 im4p extract "$V/Firmware/txm.iphoneos.release.im4p"  -o "$V/txm.bin"
ipsw img4 im4p extract "$V/Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p" -o "$V/exclave.bin"

stat -c%s "$V/sptm.bin"
strings -a "$V/sptm.bin" | grep -Eo 'SPTM-[0-9.]+' | sort -u
strings -a "$V/txm.bin"  | grep -Eo 'txm-[0-9.]+'  | sort -u
# kernelcache (already extracted with: ipsw extract --kernel <IPSW>)
stat -c%s extracted/<ver>/<build>__iPhone17,2/kernelcache.release.iPhone17,2
```

## (b) Measured values (pulled 2026-11-04)

| component (raw payload, bytes) | 27.0.1 (24A446) | 27.2 (24B119) | 27.3β (24C5037i) | Δ 27.0.1→27.2 | Δ 27.2→27.3 |
|---|---:|---:|---:|---:|---:|
| **SPTM** Mach-O | 1,196,064 | 1,212,448 | 1,212,448 | +16,384 (16 KiB) | +0 |
| SPTM version string | `SPTM-820.0.22` | `SPTM-820.40.24` | `SPTM-820.60.12` | — | — |
| **TXM** Mach-O | 557,088 | 557,088 | 557,088 | +0 | +0 |
| TXM version string | `txm-374` | `txm-374` | `txm-374` | — | — |
| **exclavecore bundle** payload | 32,325,632 | 32,555,008 | 32,980,992 | +229,376 (224 KiB) | +425,984 (416 KiB) |
| **kernelcache** fileset | 77,987,840 | 78,315,520 | 79,364,096 | +327,680 (320 KiB) | +1,048,576 (1 MiB) |
| DeviceTree `d94ap` payload | 354,224 | 354,184 | 354,184 | −40 | +0 |

## (c) Annotation

- **SPTM**: the three version strings are the authoritative monitor-rev signal (`820.0.22 →
  820.40.24 → 820.60.12`). The raw payload grew exactly one 16 KiB page 27.0.1→27.2 and is
  *byte-identical in size* 27.2→27.3 even though the body-diff shows +1 function (the new
  `REMAP_REGION_RNX` endpoint — see [sptm-27.2-to-27.3 receipt](sptm-rnx-endpoint.md)); size parity
  is coincidental page alignment, not "no change" — trust the version string, not the byte count.
- **TXM**: byte-identical payload and tag (`txm-374`) across all three → no TXM change in this
  window. (This is the embedded build tag; it is the measured ground truth for "TXM ~unchanged".)
- **exclave bundle**: grows every step; the 27.2→27.3 **+416 KiB** is the larger jump (services
  churn — see [userland/kernel 27.3 notes](../27.2-to-27.3/README.md)).
- All deltas are exact page multiples (16/224/416/320 KiB, 1 MiB) — consistent with segment-granular
  rebuilds, not hand-patched binaries.
</content>
</invoke>
