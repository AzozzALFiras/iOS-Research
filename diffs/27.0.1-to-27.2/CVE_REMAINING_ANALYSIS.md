# تحليل CVEs المتبقية — iOS 27.2 Kernel
## الثغرات غير المفحوصة من نشرة Apple الأمنية
**تاريخ:** 2026-11-09

---

## ملخص: 15 CVE في الكيرنل — التصنيف

### ✅ تم التحليل (مسارات ميتة مؤكدة أو قيد العمل)
| CVE | النوع | الحالة |
|-----|-------|--------|
| CVE-2026-112514 | Socket UAF | **⭐ قيد العمل — أقوى vector** |
| CVE-2026-112576 | CoW bypass | ❌ ميت — SIGBUS/kern_err |
| CVE-2026-112507 | IPC OOB write | ❌ ميت — grow-once design |
| CVE-2026-112665 | KASLR leak | ✅ محلول بأوراكل التوقيت |

### 🔍 يحتاج تحليل (6 CVEs واعدة)
| CVE | النوع | الباحث | التأثير | الأولوية |
|-----|-------|--------|---------|----------|
| **CVE-2026-84495** | UAF | Wang Yu | **kwrite** | ⭐⭐⭐ |
| **CVE-2026-112474** | UAF | STAR Labs | **kwrite** | ⭐⭐⭐ |
| **CVE-2026-65350** | UAF | Nebula/Pangu | corruption | ⭐⭐ |
| **CVE-2026-112679** | UAF | STAR Labs | corruption | ⭐⭐ |
| CVE-2026-112517 | UAF | Scola/Ploeg/++ | corruption | ⭐ |
| CVE-2026-112501 | Race | Karagun | crash | ⭐ |

### ⚪ أولوية منخفضة (5 CVEs)
| CVE | النوع | السبب |
|-----|-------|-------|
| CVE-2026-112606 | Type confusion | crash فقط |
| CVE-2026-112516 | UAF | crash فقط |
| CVE-2026-112698 | Memory handling | crash فقط |
| CVE-2026-112476 | OOB read | crash فقط |
| CVE-2026-112624 | Privacy bypass | لا kR/W |

---

## تحليل مفصل: الـ CVEs الواعدة

### 1. CVE-2026-84495 — UAF مع kwrite ⭐⭐⭐

| الحقل | القيمة |
|-------|--------|
| **الباحث** | Wang Yu |
| **التأثير** | `unexpected system termination or write kernel memory` |
| **PoC عام** | لا |
| **CISA KEV** | لا |

**لماذا واعد:**
- التأثير صريح: **"write kernel memory"** — هذا kwrite مباشر
- Wang Yu باحث معروف بثغرات kernel exploitable
- UAF = نفس نمط SockPuppet — exploitation pattern مثبت

**ما لا نعرفه:**
- أي subsystem (VM? IPC? network?)
- لم يُنشر أي تفاصيل تقنية
- لا نعرف إذا كان في zone معزول أم لا

**الخطوة التالية:**
- مقارنة binary diff دقيقة مع 27.2.1 عند وصول الكيرنل
- البحث عن تغييرات في VM/IPC subsystem خارج مسار الشبكة
- اختبار مع Wang Yu's previous CVEs لنمط مشترك

---

### 2. CVE-2026-112474 — UAF مع kwrite ⭐⭐⭐

| الحقل | القيمة |
|-------|--------|
| **الباحث** | Billy Jheng Bing Jhong + Pan Zhenpeng (STAR Labs) |
| **التأثير** | `unexpected system termination or write kernel memory` |
| **PoC عام** | لا |

**لماذا واعد:**
- **STAR Labs** = نفس الفريق الذي أبلغ عن CVE-2026-112514 (Socket UAF)
- التأثير: **kwrite** صريح
- STAR Labs لديهم track record ممتاز في kernel exploits (WeightBufs, etc)
- قد يكون في نفس subsystem (networking) أو subsystem مختلف

**فرضية:**
- إذا كان STAR Labs أبلغ عن CVE-2026-112514 (socket) و CVE-2026-112474 (kernel UAF آخر)
  فقد يكون الثاني في **PCB (protocol control block)** أو **NECP** أو **Skywalk**
- الـ 20+ ملف skywalk المعاد تجميعها تدعم هذه الفرضية

**الخطوة التالية:**
- تحليل diff في skywalk/channel و skywalk/mem
- البحث عن `skmem_page_count` overflow fix (سلسلة جديدة في 27.2)

---

### 3. CVE-2026-65350 — UAF مع corruption ⭐⭐

| الحقل | القيمة |
|-------|--------|
| **الباحثون** | Nebula Security, Tim Michaud (Aginor.ai), Xinru Chi (Pangu Lab) |
| **التأثير** | `unexpected system termination or corrupt kernel memory` |
| **مُصلح أيضاً في** | iOS 26.7.2 — مما يعني الثغرة موجودة منذ فترة |

**لماذا واعد:**
- **3 باحثين مستقلين** أبلغوا = ثغرة سهلة الاكتشاف
- **Pangu Lab** = تاريخ طويل في jailbreak exploitation
- مُصلح في 26.7.2 أيضاً = ليس regression جديد، بل ثغرة قديمة
- "corrupt kernel memory" يمكن تحويلها لـ kR/W

**دليل ثنائي محتمل:**
- `VM entry %p lock shared lock overflow` — سلسلة جديدة في 27.2
- قد يكون هذا VM entry lock race (CVE-2026-65350 أو CVE-2026-112501)
- Tim Michaud أيضاً credited في CVE-2026-112507 (IPC OOB) — نمط VM/IPC

**الخطوة التالية:**
- تحليل `vm_map_entry` lock handling في binary diff
- البحث عن التغييرات في `osfmk/vm/vm_map.c`

---

### 4. CVE-2026-112679 — UAF مع corruption ⭐⭐

| الحقل | القيمة |
|-------|--------|
| **الباحث** | STAR Labs (Billy + Pan) |
| **التأثير** | `unexpected system termination or corrupt kernel memory` |

**تحليل:**
- نفس فريق STAR Labs الذي أبلغ عن 112514 و 112474
- 3 CVEs من نفس الفريق = حملة بحثية منهجية
- "corrupt kernel memory" ≠ "write kernel memory" — قد يكون أقل تحكماً
- لكن corruption يمكن أن يؤدي لـ kR/W مع heap grooming صحيح

---

## ملخص الأدلة الثنائية من 27.0.1→27.2 Diff

### ملفات المصدر المعاد تجميعها (جديدة في 27.2)

**Networking (الأكثر تغييراً):**
- `uipc_socket.c`, `uipc_socket2.c` — Socket UAF fix (CVE-2026-112514)
- `uipc_mbuf.c`, `uipc_mbuf2.c` — mbuf handling
- `uipc_syscalls.c`, `uipc_usrreq.c`, `uipc_domain.c`, `uipc_proto.c`
- `kpi_socket.c`, `kpi_socketfilter.c`, `socket_flows.c`
- `necp_client.c`, `network_agent.c`
- `in_pcb.c`, `mp_pcb.c`, `in6_pcb.c`
- `pf_if.c`, `pf_ioctl.c`, `pf_norm.c`, `pf_pbuf.c`, `pf_table.c`

**Skywalk (~20 files):**
- `channel.c`, `channel_kern.c`, `channel_ring.c`, `channel_syscalls.c`
- `skmem.c`, `skmem_arena.c`, `skmem_cache.c`, `skmem_region.c`, `skmem_slab.c`
- `flow.c`, `flow_agg.c`, `flow_classifier.c`, `flow_entry.c`, `flow_manager.c`
- `flow_owner.c`, `flow_route.c`, `flow_stats.c`, `flow_track.c`
- `flowidns.c`, `netns.c`, `protons.c`
- `net_filter_event.c`, `net_thread_marks.c`

### سلاسل جديدة ذات صلة أمنية

| السلسلة | التفسير |
|---------|---------|
| `VM entry %p lock shared lock overflow` | VM entry lock race fix |
| `!os_add_overflow(*__counter, page_count, __counter)` | Skywalk page count overflow check |
| `!os_sub_overflow(*__counter, e->vmsk_page_count, __counter)` | Skywalk page count underflow check |
| `so->so_usecount > 0` (في sbunlock) | Socket reference count check |
| `(sb->sb_flags & SB_LOCK) \|\| SS_DEFUNCT` | Socket defunct state check |
| `mbuf %p len (%u) < off+len (%u+%u)` | mbuf length signed→unsigned fix |
| `rejecting AF_LINK gateway on index %u` | Routing validation |
| `-^_sofreelastref` | Socket last-ref tracepoint changed |
| `speculative_pages_freed` | VM page management counter |
| `_vfs_context_allows_unmunged_atime` | VFS access time fix |

---

## التوصيات

### الأولوية القصوى (kR/W مباشر)
1. **CVE-2026-112514** (Socket UAF) — تحليل مكتمل، جاهز لـ PoC
2. **CVE-2026-84495** (UAF kwrite) — يحتاج binary diff لتحديد الـ subsystem
3. **CVE-2026-112474** (UAF kwrite, STAR Labs) — محتمل في Skywalk/NECP

### الأولوية الثانية (corruption → kR/W ممكن)
4. **CVE-2026-65350** (UAF, Pangu) — محتمل VM entry race
5. **CVE-2026-112679** (UAF, STAR Labs) — CVE ثالث من نفس الفريق

### ملاحظة مهمة
CVE-2026-112514 يبقى **الأقوى** لأنه:
- تم تأكيد الإصلاح ثنائياً (17 دالة جديدة)
- Socket zone NOT type-isolated
- متاح من sandbox بدون entitlements
- نمط SockPuppet مثبت الاستغلالية
- CVSS 9.1 = أعلى تصنيف في القائمة

الـ CVEs الأخرى ستُفحص عند وصول كيرنل 27.2.1 للمقارنة الثلاثية (27.0.1 ↔ 27.2 ↔ 27.2.1).
