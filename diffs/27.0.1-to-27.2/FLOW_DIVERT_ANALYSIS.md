# flow_divert_pcb UAF — تحليل عميق

**تاريخ:** 2026-11-09
**الهدف:** iOS 27.0.1 (24A446) على iPhone 17,2 (A18 Pro)
**CVE المرشح:** CVE-2026-112514 (STAR Labs, CVSS 9.1)
**النوع:** Use-After-Free عبر handle lifetime mismatch

---

## 1. اكتشاف الثغرة

### الدليل من Binary Diff

مقارنة `site.struct` zones بين kernelcache 27.0.1 و 27.2:

```
# 27.0.1 — 523 zones:
site.struct flow_divert_group
site.struct flow_divert_group *
site.struct flow_divert_pcb

# 27.2 — 525 zones (+ 2 جديدة):
site.struct flow_divert_group
site.struct flow_divert_group *
site.struct flow_divert_pcb          ← تغير layout
site.struct flow_divert_pcb_handle   ← NEW TYPE ISOLATION ZONE
site.struct vm_sk_deferred_entry     ← جديد (غير مرتبط)
```

Apple فصلت `flow_divert_pcb_handle` لـ zone مستقلة = **إصلاح لثغرة UAF من خلال handle lifetime separation**.

---

## 2. تفاصيل الـ Struct

### 27.0.1 — flow_divert_pcb

| الخاصية | القيمة |
|---------|--------|
| **الحجم** | 224 bytes (0xE0) |
| **Zone** | `kalloc_type<flow_divert_pcb>.256` |
| **Type Signature** | `2211112121222222111222221112` (28 slots) |
| **الموقع** | `__DATA_CONST` offset `0xE928C8` (VA `0xfffffff007E948C8`) |
| **Pointers** | 11 من 28 slots = pointers (مواقع: +0x10, +0x18, +0x20, +0x28, +0x38, +0x48, +0x80, +0x88, +0x90, +0xD0, +0xD8) |

### 27.2 — flow_divert_pcb (بعد الإصلاح)

| الخاصية | القيمة |
|---------|--------|
| **الحجم** | 216 bytes (0xD8) — **أصغر بـ 8 bytes** |
| **Zone** | `kalloc_type<flow_divert_pcb>.256` |
| **Type Signature** | `221111212122222211222221112` (27 slots) |
| **تغييرات** | حقل pointer مُزال من +0x90، حقل pointer مُزال من +0xD0، حقل +0xD8 مُزال كلياً |

### 27.2 — flow_divert_pcb_handle (جديد)

| الخاصية | القيمة |
|---------|--------|
| **الحجم** | 16 bytes (0x10) |
| **Zone** | `kalloc_type<flow_divert_pcb_handle>.16` |
| **Type Signature** | `11` (2 pointers فقط) |
| **الموقع** | `__DATA_CONST` offset `0xE9FC28` (VA `0xfffffff007EA3C28`) |

### تغيير الحقول

```
Offset  27.0.1   27.2     ملاحظة
+0x00   DATA     DATA     
+0x08   DATA     DATA     
+0x10   PTR      PTR      
+0x18   PTR      PTR      
+0x20   PTR      PTR      
+0x28   PTR      PTR      
+0x30   DATA     DATA     
+0x38   PTR      PTR      
+0x40   DATA     DATA     
+0x48   PTR      PTR      
+0x50   DATA     DATA     
+0x58   DATA     DATA     
+0x60   DATA     DATA     
+0x68   DATA     DATA     
+0x70   DATA     DATA     
+0x78   DATA     DATA     
+0x80   PTR      PTR      
+0x88   PTR      PTR      
+0x90   PTR      DATA     ← CHANGED: pointer مُزال (كان يشير لـ handle?)
+0x98   DATA     DATA     
+0xA0   DATA     DATA     
+0xA8   DATA     DATA     
+0xB0   DATA     DATA     
+0xB8   DATA     PTR      ← CHANGED: pointer مُضاف (handle reference جديد?)
+0xC0   PTR      PTR      
+0xC8   PTR      PTR      
+0xD0   PTR      DATA     ← CHANGED: pointer مُزال
+0xD8   DATA     (removed) ← FIELD REMOVED: 8 bytes أصغر
```

---

## 3. نموذج الثغرة

### Handle Lifetime Mismatch

```
                27.0.1 (VULNERABLE)              27.2 (FIXED)
                =====================            ================
flow_divert     ┌─ flow_divert_pcb ─┐            ┌─ pcb ──┐  ┌─ handle ─┐
group has:      │  ... fields ...    │            │  ...    │  │ ptr → pcb│
                │  +0x90: *handle ─┐ │            │  ...    │  │ refcount │
                │  ...             │ │            └─────────┘  └──────────┘
                │  +0xD0: *??? ───┘ │              مستقل        مستقل
                └───────────────────┘
                ^                                 ^             ^
                |                                 |             |
           free on close()                   free on close  free when
                |                                            refcount=0
                v
           HANDLE STILL LIVES
           → dereference = UAF
```

### سيناريو الاستغلال

1. **إنشاء socket مع flow_divert:**
   ```c
   int sock = socket(AF_INET, SOCK_STREAM, 0);
   connect(sock, server_addr, ...);
   // إذا VPN/content filter مفعّل → kernel يخصص flow_divert_pcb
   ```

2. **Race condition: close أثناء processing:**
   ```c
   // Thread 1: يغلق السوكيت
   close(sock);  // → يحرر flow_divert_pcb
   
   // Thread 2: لا يزال يعالج بيانات flow_divert
   // → يصل لـ pcb المحرر عبر handle → UAF
   ```

3. **Reclaim:**
   ```c
   // الـ freed 224-byte allocation في kalloc_type<flow_divert_pcb>.256
   // يمكن استبداله بـ flow_divert_pcb آخر (same type → same zone)
   for (int i = 0; i < 1000; i++) {
       sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
       connect(sockets[i], server_addr, ...);
   }
   // الآن الـ handle يشير لـ pcb مختلف → type confusion
   ```

---

## 4. الوصول من App Sandbox

### طريقة 1: VPN/Content Filter (الأسهل)
- إذا الجهاز عنده VPN profile مثبت (شائع على MDM)
- أي socket() → connect() يُنشئ flow_divert_pcb تلقائياً
- لا يحتاج entitlement خاص من التطبيق

### طريقة 2: setsockopt مباشر
- `setsockopt(sock, SOL_SOCKET, SO_NECP_ATTRIBUTES, ...)`
- قد يفعّل flow_divert path بدون VPN
- يحتاج التحقق على الجهاز

### طريقة 3: Self-VPN Trigger
- التطبيق يسجل كـ Network Extension provider
- يحتاج `com.apple.developer.networking.networkextension` entitlement
- لكن يمكن الحصول عليه من App Store بشكل شرعي (VPN apps)

### تقييم CVSS 9.1 "Network Reachable"
- "Network" هنا يعني الثغرة في networking subsystem
- يمكن trigger عبر حزم شبكة واردة أثناء flow_divert processing
- مثلاً: إرسال RST packet في اللحظة الصحيحة لتسريع close path

---

## 5. علاقة بإصلاحات أخرى في 27.2

### "Disallow request nexus with flow divert result"
- فحص أمني جديد في 27.2
- يمنع إنشاء Skywalk nexus على socket مع flow_divert
- في 27.0.1: يمكن الجمع بين flow_divert و nexus → سطح هجوم أوسع

### mbuf signed → unsigned
```
27.0.1: %s: mbuf %p len (%d) < off+len (%d+%d)
27.2:   %s: mbuf %p len (%u) < off+len (%u+%u)
```
- تغيير مرتبط — mbuf length check في socket path

---

## 6. خطة العمل

### المرحلة 1: تأكيد الوصول (يوم واحد)
1. على الجهاز (27.0.1): اختبار ما إذا كان flow_divert_pcb يُخصص بدون VPN
2. اختبار `setsockopt` paths المختلفة
3. تأكيد zone: `zprint | grep flow_divert`

### المرحلة 2: تحديد Race Window (يومان)
1. عكس flow_divert_pcb_create/destroy في 27.0.1 باينري
2. تحديد أين يُخزن handle pointer (offset +0x90 أو +0xD0)
3. تحديد أي code path يصل handle بعد free
4. قياس timing window

### المرحلة 3: بناء PoC (3 أيام)
1. Trigger UAF عبر socket close race
2. Reclaim بـ flow_divert_pcb آخر أو zone GC → page-level
3. تأكيد controlled data في UAF allocation
4. قراءة/كتابة عبر confused pcb fields

### المرحلة 4: kR/W Primitive (3 أيام)
1. استخدام pointer fields في pcb لقراءة kernel memory
2. أو: zone GC لتحويل typed allocation لـ page-level control
3. بناء stable read/write primitive

---

## 7. تقييم المخاطر

| العامل | التقييم |
|--------|---------|
| **الدليل على الثغرة** | قوي جداً — type isolation fix + struct shrink + handle extraction |
| **الوصول من Sandbox** | متوسط — يحتاج VPN أو triggering mechanism |
| **Type Isolation** | pcb في zone مخصصة — يحتاج page-level reclaim |
| **Timing Window** | غير معروف — يحتاج binary analysis |
| **CVE Attribution** | CVE-2026-112514 (احتمال 70%) |
| **احتمال النجاح** | 40-60% (أعلى من أي lead سابق) |

---

## 8. ملاحظات هامة

- هذا **أقوى lead حتى الآن** — type isolation fix + struct layout change = دليل قوي على ثغرة حقيقية
- لكن Type Isolation تعقّد الاستغلال — لا يمكن spray بـ struct مختلف
- الحل: page-level reclaim عبر zone GC (مثل kfd)، أو same-type confusion
- `flow_divert_pcb_handle` = 16 bytes فقط (2 pointers) — هذا indirection object صغير، مثالي لـ dangling pointer
- الإصلاح في 27.2 يعطي lifetime مستقلة لكل من pcb و handle — مما يؤكد أن المشكلة كانت في shared lifetime
