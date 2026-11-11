# ملخص الطرق الميتة — iOS 27.0.1 / iPhone 17,2 (A18 Pro)

**تاريخ التوليد:** 2026-11-09
**الغرض:** مرجع سريع لتحليل فيرموير 27.2.1 — تجنّب كل ما هو مذكور هنا

---

## الإحصائيات

| الفئة | عدد المسارات الميتة | أهم آلية القتل |
|-------|---------------------|----------------|
| KASLR Info Leak | 7 | Apple يصفّر كل kernel pointers (غير مهم — KASLR محلول) |
| GPU / Metal | 4 | عزل DART/UAT — GPU لا يصل kernel memory |
| IOSurface Overflow | 2 | الكيرنل يرفض compressionType=3 ويثبت sliceCount=1 |
| AVE / Video Encoder | 4 | VT userspace يتحقق قبل الكيرنل + bounds checks باينري |
| AVC / Video Codec | 2 | VT userspace يرفض log2_fn>16 قبل الكيرنل |
| IPC / Mach Port | 2 | Table grows مرة واحدة — لا race window |
| ANE / Neural Engine | 1 | حاجز معماري: aned daemon يتوسط كل الوصول |
| SPTM | 3 | يحتاج EL2/EL3 أو kernel compromise مسبق |
| IOMFB / Display | 1 | لا يوجد في kernelcache — DCP firmware |
| Handle Race Strategies | 4 | Type Isolation تعزل الـ zones |
| ScalerCSC | 1 | لا struct input — zero attack surface |
| External | 1 | iOS خاطئ + يعتمد على primitive ما عندنا |
| **المجموع** | **28+** | |

**CVEs ميتة مؤكدة:** 10
**باقات مأكدة من 27.0.1→27.2:** 14 (كلها variant-hunted، كلها سلبية)

---

## أهم الدروس المستفادة

### 1. Type Isolation تقتل أي heap spray
`kalloc_type<IOSurface>.1024` معزولة عن `kalloc_data`. لا يمكن لأي spray من zone تملأ فراغ zone أخرى.
**الحل:** العمل على مستوى الصفحات الفيزيائية (kfd) أو VM/VFS (DarkSword/ClearSword).

### 2. VideoToolbox هو الحارس الأول لكل AVE/AVC
أي overflow في bitstream fields يُرفض في userspace قبل أن يصل الكيرنل. AppleAVE2 checks = defense-in-depth فقط.

### 3. DART يعزل GPU عن الكيرنل hardware-level
لا يوجد مسار من GPU VA إلى kernel PA. حتى F1OOB (100% reliable) لا يمكنها الهروب.

### 4. XPC daemons تحرس hardware accelerators
ANE (aned)، DCP (dcpd) — كلها وراء XPC gates. `kIOReturnNotPermitted` من الساندبوكس.

### 5. Grow-once designs تقتل race conditions
IPC request table تنمو مرة واحدة ثم freelist تتولى. لا race window ممكن.

### 6. الجيلبريكات الناجحة تعمل فوق type isolation
kfd (PUAF)، ClearSword (VFS OOB)، WeightBufs (DMA)، DarkSword (CoW) — كلها على المستوى الفيزيائي/VM/VFS.

---

## ما يجب تجنبه في تحليل 27.2.1

1. **لا تضيع وقت على AppleAVE2 SPS/PPS/VPS/MMCO diffs** — كلها defense-in-depth وراء VT
2. **لا تحلل IOSurface compressionType/sliceCount** — الكيرنل يثبت القيم
3. **لا تحلل ANE/AppleH16ANEInterface** — unreachable من الساندبوكس
4. **لا تحلل IOMobileFrameBuffer** — DCP firmware، ليس في kernelcache
5. **لا تحلل ScalerCSC** — لا struct input، لا attack surface
6. **لا تحلل GPU/DART PTE** — عزل hardware
7. **لا تحلل IPC port request table** — grow-once architecture
8. **لا تبني على أي spray-based kR/W** — type isolation تمنع
9. **تخطّ diffs الي فقط logging/assertion/telemetry** — لا تغيير سلوكي

### ركّز بدلاً على:
- **IOMemoryDescriptor lifecycle** — page-level، يتجاوز type isolation
- **IOKit structs جديدة (2024+)** — سطح هجوم غير ممسوح
- **DER/ASN.1 parsing** — buffer overflow potential
- **VFS/UPL layer** — نفس مستوى DarkSword
- **vm_map entry handling** — CoW class bugs
- **Bluetooth/WiFi/USB kext changes** — سطح هجوم أقل تمشيطاً

---

## الـ 3 Leads غير المأكدة (من workflow 2026-11-09)

### 1. AVD-SHARED-BUFFER-LIFECYCLE ⭐ الأقوى
- **المكون:** AppleAVD createSharedBuffer (#29) / destroySharedBuffer (#30)
- **لماذا واعد:** تخصيصات على مستوى الصفحات (IOMemoryDescriptor) → تتجاوز Type Isolation. Race عند destroy أثناء decode → physical page UAF
- **الخطوة التالية:** فك تشفير methods #29-30، فحص المزامنة (locks/barriers)
- **الحالة:** لم يُفحص بعد

### 2. JPEG-STRUCT-INPUT-2024
- **المكون:** AppleJPEGDriverIOStruct2024 (جديد في iOS 27)
- **لماذا واعد:** width×height overflow → DART يخصص صفحات أقل → codec DMA OOB
- **الخطوة التالية:** عكس IOStruct2024 layout، fuzz الأبعاد
- **الحالة:** لم يُفحص بعد

### 3. SEPKEYSTORE-DER-OOB
- **المكون:** SEPKeyStore DER parsing
- **لماذا واعد:** 27.2 أضاف "device state der too big to cache" — غير موجود في 27.0.1
- **المخاطر:** على الأرجح يحتاج entitlement خاص من الساندبوكس
- **الخطوة التالية:** اختبار IOServiceOpen من التطبيق
- **الحالة:** لم يُفحص بعد

---

## ملاحظة ختامية

28 مسار ميت = 0% معدل تحويل. احتمال بقاء أي lead جديد بعد التحليل العميق: **25-35%**.
AVD shared buffer هو الأقوى لأنه page-level ويصل من الساندبوكس.

**الملف المرجعي الكامل:** `DEAD_PATHS_BLACKLIST.json` (نفس المجلد)
