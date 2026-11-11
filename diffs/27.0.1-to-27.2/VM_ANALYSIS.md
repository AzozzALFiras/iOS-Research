# تحليل تغييرات VM / الذاكرة / الشبكة — iOS 27.0.1 → 27.2

**تاريخ:** 2026-11-09
**الهدف:** iPhone 17,2 (A18 Pro) — iOS 27.0.1 (24A446)
**المقارنة:** kernelcache 27.0.1 (24A446) vs kernelcache 27.2 (24B119)

---

## 1. ملخص تنفيذي

تحليل مقارنة strings + type metadata بين kernelcache 27.0.1 و 27.2 كشف عن:
- **2 type isolation zones جديدة** (من 523 → 525)
- **6 overflow checks جديدة** غائبة تماماً في 27.0.1
- **~190 ملف XNU مُعاد تجميعه** — أكثر من 60% منها networking/socket/skywalk
- **ثغرة flow_divert UAF** مع تغيير struct layout + type isolation fix
- **وحدة vm_sk_deferred جديدة كلياً** لإدارة صفحات Skywalk المؤجلة
- **1 ملف XNU جديد كلياً**: `iptap.c`

---

## 2. Type Isolation Zones الجديدة

### 2.1 `flow_divert_pcb_handle` ⭐⭐⭐ الأهم

| الخاصية | القيمة |
|---------|--------|
| **وجود في 27.0.1** | ❌ لا يوجد |
| **وجود في 27.2** | ✅ `site.struct flow_divert_pcb_handle` |
| **الملف المصدري** | `bsd/netinet/flow_divert.c` |
| **التأثير** | في 27.0.1، `flow_divert_pcb` و handles تُخصص من نفس الـ zone → type confusion/UAF ممكن |

**الدليل:**
```
# 27.0.1 — 3 zones فقط:
site.struct flow_divert_group
site.struct flow_divert_group *
site.struct flow_divert_pcb

# 27.2 — 4 zones (+ pcb_handle):
site.struct flow_divert_group
site.struct flow_divert_group *
site.struct flow_divert_pcb
site.struct flow_divert_pcb_handle   ← NEW
```

**تغيير struct layout:**
```
27.0.1 type sig: 22111121212222221111222221112
27.2   type sig: 22111121212222221122222111​2
                                    ^^^^^^^^^^^^  ← تغيير في pointer/data layout
```

الأرقام `1` = pointers، `2` = data. التغيير في المواقع 18-28 يعني Apple أضافت/أزالت/نقلت حقول pointer في الـ struct.

**تقييم للاستغلال:**
- ✅ type confusion بين `flow_divert_pcb` و `flow_divert_pcb_handle` في 27.0.1
- ✅ الوصول عبر `com.apple.flow-divert` entitlement (تطبيقات VPN / Network Extensions)
- ⚠️ يحتاج التحقق: هل يمكن الوصول من app sandbox بدون entitlement خاص؟
- **CVE المرشح:** CVE-2026-112514 (STAR Labs, CVSS 9.1, network-reachable UAF)

**إصلاحات إضافية في 27.2:**
- `"Disallow request nexus with flow divert result"` — فحص أمني جديد يمنع طلب nexus عبر flow_divert
- هذا بالإضافة للفحص الموجود: `"Disallow flow add with flow divert result"`

### 2.2 `vm_sk_deferred_entry`

| الخاصية | القيمة |
|---------|--------|
| **وجود في 27.0.1** | ❌ لا يوجد |
| **وجود في 27.2** | ✅ `site.struct vm_sk_deferred_entry` |
| **الملف المصدري** | `vm_sk_deferred.c` (ملف جديد كلياً) |
| **التأثير** | وحدة جديدة لإدارة تأجيل تحرير صفحات Skywalk |

**Strings جديدة:**
```
vm_sk_deferred.c
vm_sk_deferred_drain
vm_sk_deferred: failed to start drain thread (%d)
memorystatus: purged %llu KiB of deferred SK pages
site.struct vm_sk_deferred_entry
```

**تقييم:**
- هذه **ميزة جديدة** وليست إصلاح لثغرة موجودة
- الـ drain thread قد يحتوي race conditions (كود جديد = أقل اختبار)
- لكن Skywalk عموماً يحتاج entitlements خاصة

---

## 3. Overflow Checks الجديدة (غائبة في 27.0.1) ⭐⭐

### 3.1 Page Count Arithmetic Overflow

```c
// 27.2 فقط — 27.0.1 لا يتحقق:
!os_add_overflow(*__counter, page_count, __counter)
!os_sub_overflow(*__counter, e->vmsk_page_count, __counter)
```

**تقييم:**
- في 27.0.1، عمليات حسابية على عدادات الصفحات **لا تتحقق من overflow**
- integer overflow في page counter يمكن أن يؤدي لتخصيص أقل من المطلوب
- مرتبط بوحدة `vm_sk_deferred` — قد لا يكون قابلاً للاستغلال إذا الوحدة كلها غير موجودة في 27.0.1
- **CVE المرشح:** CVE-2026-84495 (Wang Yu) أو CVE-2026-112474 (STAR Labs) — كلاهما "kernel write"

### 3.2 VM Entry Lock Shared Overflow

```c
// 27.2 فقط:
VM entry %p lock shared lock overflow <v:%d c:%c%c w:%c%c %c/%d>
```

**تقييم:**
- عداد shared lock على vm_map_entry يمكن أن يتجاوز الحد الأقصى
- في 27.0.1 لا يوجد كشف لهذا — overflow صامت
- **خطير إذا كان wrapping integer**: counter يعود لصفر → lock يصبح unlocked → race condition → UAF
- يحتاج تحقق باينري: هل العداد 8-bit أم 16-bit أم 32-bit؟
- **CVE المرشح:** CVE-2026-112474 (STAR Labs, kernel arbitrary write)

### 3.3 Segment Limit Overflow

```c
// 27.2 فقط:
vm: configured segment limit would overflow slot mapping index, reducing to %d
```

**تقييم:**
- إصلاح لحالة تمنع segment limit من التسبب بـ overflow في slot mapping
- في 27.0.1 هذا يمكن أن يؤدي لـ OOB write في جدول slots
- **خطير إذا كان reachable** — يحتاج التحقق من كيف يتم تكوين segment limits

### 3.4 Video Overflow/Underflow

```
videoOverflow
videoUnderflow
```

- على الأرجح مرتبطة بـ video buffer management
- تحتاج تحقق إضافي في سياق AppleAVD/AVE

---

## 4. تغييرات Socket / Networking

### 4.1 mbuf Length Check — Signed → Unsigned

```
# 27.0.1:
%s: mbuf %p len (%d) < off+len (%d+%d)

# 27.2:
%s: mbuf %p len (%u) < off+len (%u+%u)
```

**تقييم:**
- `%d` → `%u` يعني signed → unsigned comparison
- **إذا كان الفحص signed في 27.0.1**: قيمة سالبة للطول تتجاوز الفحص → OOB read/write
- الملفات المتأثرة: `kpi_mbuf.c` أو `uipc_mbuf.c`
- **CVE المرشح:** CVE-2026-112514 (ثاني أقوى احتمال بعد flow_divert)

### 4.2 pktap Rewrite

```
# 27.0.1:
pktap_bpf_tap    ← تمت إزالته

# 27.2:
pktap_build_mbuf_header   ← جديد
pktap != NULL              ← NULL assertion جديد
```

**تقييم:**
- pktap تمت إعادة كتابته كلياً
- NULL check مفقود في 27.0.1 → NULL deref (DoS فقط مع SPTM)
- `pktap_bpf_tap` ← الوظيفة القديمة أُزيلت واستُبدلت بـ `pktap_build_mbuf_header`

### 4.3 Skywalk Packet Filter Changes

```
# 27.2 فقط:
SK[%u]: %-30s filter packet is not mbuf-wrapped: pkt_pflags 0x%llx
SK[%u]: %-30s filter packet is not packet-wrapped: pkt_pflags 0x%llx
SK[%u]: %-30s dropped packet injected on ring %u whose wrap flag does not match the ring direction
nx_netif_filter_pkt_to_mbuf
nx_netif_filter_pkt_to_pkt
```

**تقييم:**
- Apple أضافت فحوصات جديدة لنوع الـ packet wrapping
- في 27.0.1 يمكن تمرير packet بـ wrap flags خاطئة → type confusion في packet processing
- يحتاج Skywalk entitlements

### 4.4 NECP Socket Resolver

```
# 27.2 فقط:
necp_set_socket_resolver_signature_from_parameters
```

- دالة جديدة في NECP subsystem
- تحتاج تحقق إضافي

---

## 5. تغييرات Page/Memory Management

### 5.1 Page Integrity — Framebank

```
# 27.2 فقط:
Page modified after framebank withdraw %p
```

**تقييم:**
- Apple أضافت integrity check بعد سحب صفحة من framebank
- في 27.0.1 لا يوجد هذا الفحص → يمكن تعديل صفحة أثناء عملية السحب
- **مثير**: يشير إلى أن 27.0.1 ربما يسمح بتعديل محتوى صفحة بين السحب والاستخدام

### 5.2 Speculative Page Queue

```
# 27.2 فقط:
speculative_pages_demoted
speculative_pages_freed
speculative_pages_requeued_inactive
The lifetime number of pages freed while still on the speculative queue...
The lifetime number of pages that already held content and were put on the speculative queue...
```

**تقييم:**
- إحصائيات جديدة لإدارة الصفحات المضاربة
- تحسين أداء + مراقبة — ليس إصلاح ثغرة مباشر
- لكن يشير لتغييرات في page lifecycle logic

### 5.3 Swap Control

```
# 27.0.1:
memorystatus: swap is disabled, bypassing fast-wake warmup  ← أُزيل

# 27.2:
Controls whether applications are eligible to have their memory swapped under pressure  ← جديد
swap_all_apps  ← sysctl جديد
```

**تقييم:**
- تغيير في سياسة الـ swap — ميزة جديدة وليست إصلاح أمني

### 5.4 UPL Mapping Changes

```
# 27.0.1:
error %d mapping UPL, upl_f_offset %llu, upl_len %d
error %d unmapping UPL, upl_f_offset %llu, upl_len %d

# 27.2:
(أُزيلت — يعني تمت إعادة كتابة error handling)
```

**تقييم:**
- UPL (Universal Page List) mapping error strings أُزيلت
- إما أُعيد كتابة الوظائف أو أُدمجت في error handling موحد
- UPL هو المستوى الذي تعمل عليه بعض الجيلبريكات (DarkSword)

### 5.5 CoW External Objects

```
# 27.0.1 فقط:
External objects are not implemented for CoW. %p %i %i %llx %llx

# 27.2:
(أُزيل)
```

**تقييم مهم:**
- هذه الرسالة في 27.0.1 تقول "external objects غير مدعومة لـ CoW"
- إزالتها في 27.2 تعني إما:
  1. تم تنفيذ الدعم (بعيد)
  2. أو تمت إزالة مسار الكود بالكامل
- **مرتبط بـ CoW bypass research السابق** — لكن كان DEAD بسبب zero-fill

### 5.6 vm_protect_privileged_from_untrusted

```
# 27.0.1 فقط:
vm_protect_privileged_from_untrusted

# 27.2:
(أُزيل)
```

**تقييم:**
- mitigation string مُزال → إما أُعيد تسمية أو أُدمج في مسار آخر
- **يحتاج تحقق**: هل Apple أزالت هذا الفحص الأمني أم نقلته؟

---

## 6. تغييرات Vnode / APFS

```
# 27.2 فقط:
%s: %s: read advise vnode: %p fileOffset: %lld fileSize: 0x%llx
%s: %s: vnode_rdadvise vp=%p fileOffset=%lld len=%d
[ERROR] %s: %s: Read advise: vnode_get failed, ret=%d
[ERROR] %s: %s: vnode read advise failed, ret=%d
[ERROR] %s: %s: vnode_rdadvise failed at off=%lld len=%d, ret=%d
%s:%d: %s Cannot decompress data from inode %lld on a sealed volume
```

**تقييم:**
- Apple أعادت كتابة vnode read advise — error handling أفضل
- "`Cannot decompress data from inode on a sealed volume`" — فحص جديد لسلامة البيانات
- ليس إصلاح ثغرة مباشر — تحسينات defensive

---

## 7. ملفات XNU المعاد تجميعها

### إحصائيات:
| الفئة | عدد الملفات |
|-------|-------------|
| Socket / UIPC | 12 |
| TCP / IP / UDP | 35+ |
| Skywalk (channel, nexus, packet, mem) | 50+ |
| Network Interface (dlil, if_*) | 15+ |
| PF Firewall | 6 |
| NECP | 2 |
| IPSec | 8 |
| APFS | 2 |
| CLPC / Power | 15+ |
| **المجموع** | **~190** |

### الملاحظة الأهم:
**أكثر من 60% من التغييرات في networking subsystem** — هذا يتوافق مع CVE-2026-112514 (network-reachable UAF).

---

## 8. ترتيب الأهداف للاستغلال

### 🥇 المرتبة 1: flow_divert_pcb UAF / Type Confusion
- **الدليل:** type isolation zone جديدة + struct layout change + security check جديد
- **الوصول:** `com.apple.flow-divert` entitlement (VPN/NetworkExtension apps)
- **النوع:** UAF / type confusion → kR/W
- **CVE:** CVE-2026-112514 (STAR Labs, CVSS 9.1)
- **الخطوة التالية:** عكس `flow_divert_pcb` struct في 27.0.1، تحديد race window، بناء PoC

### 🥈 المرتبة 2: VM Entry Lock Counter Overflow
- **الدليل:** overflow detection string غائب تماماً في 27.0.1
- **الوصول:** vm_map operations من أي process
- **النوع:** integer overflow → lock bypass → race → UAF
- **CVE:** CVE-2026-112474 أو CVE-2026-84495
- **الخطوة التالية:** تحديد حجم العداد، بناء PoC لتجاوزه

### 🥉 المرتبة 3: Segment Limit Slot Mapping Overflow
- **الدليل:** overflow protection string غائب في 27.0.1
- **الوصول:** يحتاج تحقق — ربما عبر vm_map configuration
- **النوع:** OOB write في slot mapping table
- **الخطوة التالية:** تحديد كيف يتم تكوين segment limits

### المرتبة 4: mbuf Signed Length Check
- **الدليل:** `%d` → `%u` format string change
- **الوصول:** network packet processing
- **النوع:** signed comparison bypass → OOB access
- **الخطوة التالية:** تحديد الدالة الدقيقة وبناء packet خبيث

### المرتبة 5: Page Integrity After Framebank Withdraw
- **الدليل:** integrity check غائب في 27.0.1
- **الوصول:** يحتاج تحقق — ربما عبر memory pressure
- **النوع:** page content modification → confused deputy

---

## 9. العلاقة بالمسارات الحية الحالية

| المكون | الحالة | التوافق مع هذا التحليل |
|--------|--------|------------------------|
| HandleRace ✅ | يعمل | flow_divert UAF = بديل مستقل |
| KASLR ✅ | محلول | لا تغيير |
| F1OOB (IOSurface) | حي | لا تغيير |
| AVD Shared Buffer | غير مفحوص | لا صلة مباشرة |
| JPEG Struct 2024 | غير مفحوص | لا صلة مباشرة |

---

## 10. التوصيات

1. **الأولوية القصوى:** عكس `flow_divert_pcb` / `flow_divert_pcb_handle` في kernelcache 27.0.1 لتحديد:
   - حجم كل struct
   - الـ kalloc zone المشتركة
   - نقطة الـ race condition (connect/disconnect/destroy)
   - كيف يُخصص pcb_handle ويُحرر

2. **التحقق من الوصول:** اختبار ما إذا كان `flow_divert` يحتاج entitlement خاص أو يمكن الوصول إليه من app sandbox مباشرة

3. **VM Entry Lock:** تحديد حجم lock counter عبر binary analysis — إذا كان 8-bit أو 16-bit فالـ overflow أسهل

4. **انتظار 27.2.1:** مقارنة 27.2 vs 27.2.1 قد تكشف fixes إضافية لنفس الثغرات (أو ثغرات جديدة أُضيفت في 27.2)
