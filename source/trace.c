// SPDX-License-Identifier: MIT
#include "trace.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

extern const u8 nup_trace_tramp_table[];

typedef struct {
    u64 target;
    const char* name;
    const char* mod_name;
    volatile u32 hits;
    u32 logged;
    u64 first_x0;
    u64 first_x1;
    u64 first_lr;
} TraceSlot;

typedef struct {
    volatile u64 seq;       // 0 while writer active; nonzero = committed sequence
    u32 slot_idx;
    u32 reserved;
    u64 caller_lr;
    u64 x0;
    u64 x1;
    u64 x2;
    u64 x3;
    u64 timestamp;          // CNTPCT_EL0
} TraceRingEntry;

static bool g_trace_enabled = false;
static const ModuleSet* g_trace_mods = NULL;
static TraceSlot g_slots[NUP_TRACE_MAX_SLOTS];
static u32 g_slot_count = 0;
static u32 g_overflow_count = 0;

// Persistent string copies for dynamic procs (e.g. nvnDeviceGetProcAddress) whose
// caller-supplied name strings may live in temporary stack buffers.
#define MAX_DYN_NAME_STORAGE 8192u
static char g_dyn_names[MAX_DYN_NAME_STORAGE];
static u32 g_dyn_name_pos = 0;

static TraceRingEntry g_ring[NUP_TRACE_RING_SIZE];
static volatile u64 g_ring_seq = 0;
static u64 g_last_drained_seq = 0;
static u64 g_dropped_total = 0;

static u64 g_hb_last_seq = 0;
static u32 g_hb_inactive_ms = 0;
static bool g_hb_snapshot_dumped = false;

static inline u64 read_cntpct(void) {
    u64 v = 0;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(v));
    return v;
}

void nupTraceReset(bool enabled) {
    g_trace_enabled = enabled;
    g_trace_mods = NULL;
    g_slot_count = 0;
    g_overflow_count = 0;
    g_dyn_name_pos = 0;
    g_ring_seq = 0;
    g_last_drained_seq = 0;
    g_dropped_total = 0;
    g_hb_last_seq = 0;
    g_hb_inactive_ms = 0;
    g_hb_snapshot_dumped = false;
    memset(g_slots, 0, sizeof(g_slots));
    memset(g_ring, 0, sizeof(g_ring));
}

bool nupTraceIsEnabled(void) {
    return g_trace_enabled;
}

void nupTraceSetModules(const ModuleSet* set) {
    g_trace_mods = set;
}

u32 nupTraceSlotCount(void) {
    return g_slot_count;
}

u32 nupTraceOverflowCount(void) {
    return g_overflow_count;
}

u64 nupTraceTotalSeq(void) {
    return __atomic_load_n(&g_ring_seq, __ATOMIC_ACQUIRE);
}

u64 nupTraceDroppedCount(void) {
    return g_dropped_total;
}

static bool is_noisy_symbol(const char* name) {
    static const char* const skip_substrs[] = {
        "LockMutex", "UnlockMutex", "TryLockMutex",
        "LockLightLock", "UnlockLightLock", "TryLockLightLock",
        "LockRecursiveMutex", "UnlockRecursiveMutex",
        "GetCurrentThread", "GetSystemTick", "ConvertToTimeSpan",
        "GetTlsValue", "SetTlsValue",
        "GetCurrentProcessorNumber",
        "YieldThread", "SleepThread",
        "GetStandardAllocator", "Allocate", "Free",
        NULL
    };
    const bool keep_alloc = (strstr(name, "AddressRegion") != NULL ||
                             strstr(name, "MemoryPages") != NULL ||
                             strstr(name, "MemoryBlock") != NULL ||
                             strstr(name, "UnitHeap") != NULL ||
                             strstr(name, "TlsSlot") != NULL);
    for (int i = 0; skip_substrs[i]; i++) {
        if (keep_alloc && (strcmp(skip_substrs[i], "Allocate") == 0 || strcmp(skip_substrs[i], "Free") == 0))
            continue;
        if (strstr(name, skip_substrs[i]) != NULL)
            return true;
    }
    return false;
}

bool nupTraceShouldWrap(const char* mod_name, const char* name) {
    if (!name || !name[0])
        return false;
    if (mod_name && strcmp(mod_name, "sdk") == 0)
        return false;
    if (is_noisy_symbol(name))
        return false;

    const bool is_compat = (mod_name && (strcmp(mod_name, "compat1") == 0 || strcmp(mod_name, "compat2") == 0));
    if (is_compat) {
        return (strncmp(name, "_ZN2nn", 6) == 0 ||
                strncmp(name, "_ZNK2nn", 7) == 0 ||
                strncmp(name, "nnos", 4) == 0 ||
                strncmp(name, "nninit", 6) == 0 ||
                strncmp(name, "nvn", 3) == 0 ||
                strncmp(name, "pfnc_nvn", 8) == 0 ||
                strncmp(name, "_ZN7android", 11) == 0);
    }

    static const char* const prefixes[] = {
        "_ZN2nn2fs", "_ZNK2nn2fs",
        "_ZN2nn3aoc", "_ZNK2nn3aoc",
        "_ZN2nn2oe", "_ZNK2nn2oe",
        "_ZN2nn2am", "_ZNK2nn2am",
        "_ZN2nn2sm", "_ZNK2nn2sm",
        "_ZN2nn2os", "_ZNK2nn2os",
        "_ZN2nn3mem", "_ZNK2nn3mem",
        "_ZN2nn4lmem", "_ZNK2nn4lmem",
        "_ZN2nn2vi", "_ZNK2nn2vi",
        "_ZN2nn2nv", "_ZNK2nn2nv",
        "_ZN2nn7account", "_ZNK2nn7account",
        "_ZN2nn4init", "_ZN2nn4diag",
        "_ZN2nn6compat", "_ZN2nn2ro",
        "_ZN2nn5audio", "_ZN2nn3hid",
        "_ZN2nn4nifm", "_ZN2nn6socket",
        "_ZN2nn4time", "_ZN2nn8settings",
        "nninit", "nvn",
        NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0)
            return true;
    }
    return false;
}

static u64 alloc_slot(const char* mod_name, const char* sym_name, u64 target_addr, bool copy_name) {
    for (u32 i = 0; i < g_slot_count; i++) {
        if (g_slots[i].target == target_addr && strcmp(g_slots[i].name, sym_name) == 0) {
            return (u64)(uintptr_t)(nup_trace_tramp_table + (size_t)i * 8u);
        }
    }
    if (g_slot_count >= NUP_TRACE_MAX_SLOTS) {
        g_overflow_count++;
        if (g_overflow_count <= 8) {
            nupLogf("[trace] WARNING: trampoline pool FULL (%u/%u), omitted [%s] %s\n",
                    g_slot_count, NUP_TRACE_MAX_SLOTS, mod_name ? mod_name : "?", sym_name);
        }
        return 0;
    }

    const char* stored_name = sym_name;
    if (copy_name) {
        const size_t nlen = strlen(sym_name) + 1u;
        if (g_dyn_name_pos + nlen <= MAX_DYN_NAME_STORAGE) {
            memcpy(g_dyn_names + g_dyn_name_pos, sym_name, nlen);
            stored_name = g_dyn_names + g_dyn_name_pos;
            g_dyn_name_pos += (u32)nlen;
        } else {
            return 0;
        }
    }

    const u32 idx = g_slot_count++;
    g_slots[idx].target = target_addr;
    g_slots[idx].name = stored_name;
    g_slots[idx].mod_name = mod_name ? mod_name : "?";
    g_slots[idx].hits = 0;
    g_slots[idx].logged = 0;
    return (u64)(uintptr_t)(nup_trace_tramp_table + (size_t)idx * 8u);
}

u64 nupTraceWrapPlt(const char* mod_name, const char* sym_name, u64 target_addr) {
    if (!g_trace_enabled || !target_addr || !nupTraceShouldWrap(mod_name, sym_name))
        return 0;
    return alloc_slot(mod_name, sym_name, target_addr, false);
}

static bool is_interesting_nvn_proc(const char* name) {
    // Wrap lifecycle / pool / queue / window / shader / device NVN procs (skip per-draw hot calls)
    static const char* const nvn_keys[] = {
        "nvnDeviceInitialize", "nvnDeviceFinalize",
        "nvnDeviceGetInteger", "nvnDeviceSetWindowOriginMode",
        "nvnMemoryPoolInitialize", "nvnMemoryPoolFinalize",
        "nvnQueueInitialize", "nvnQueueFinalize", "nvnQueuePresentTexture",
        "nvnWindowInitialize", "nvnWindowFinalize", "nvnWindowAcquireTexture",
        "nvnCommandBufferInitialize", "nvnProgramInitialize",
        "nvnSyncInitialize", "nvnTexturePoolInitialize", "nvnSamplerPoolInitialize",
        NULL
    };
    for (int i = 0; nvn_keys[i]; i++) {
        if (strcmp(name, nvn_keys[i]) == 0)
            return true;
    }
    return false;
}

u64 nupTraceWrapDynamicProc(const char* source, const char* proc_name, u64 target_addr) {
    if (!g_trace_enabled || !target_addr || !proc_name || !proc_name[0])
        return 0;
    if (!is_interesting_nvn_proc(proc_name))
        return 0;
    return alloc_slot(source ? source : "nvn_gpa", proc_name, target_addr, true);
}

// HOT PATH: called from nup_trace_common in trace_tramp.s.
// Preserves target pointer untouched (including any PAC bits on target).
// Must remain 100% lock-free, syscall-free, heap-free, and TLS/newlib-free!
u64 nupTraceRecord(u32 slot_idx, u64 lr, u64 x0, u64 x1, u64 x2, u64 x3) {
    if (slot_idx >= g_slot_count)
        return 0;
    TraceSlot* s = &g_slots[slot_idx];
    const u64 target = s->target;
    const u64 clean_lr = lr & 0x0000007fffffffffULL;

    const u32 prev_hits = __atomic_fetch_add(&s->hits, 1u, __ATOMIC_RELAXED);
    if (prev_hits == 0) {
        s->first_x0 = x0;
        s->first_x1 = x1;
        s->first_lr = clean_lr;
    }

    const u64 seq = __atomic_fetch_add(&g_ring_seq, 1ULL, __ATOMIC_RELAXED) + 1ULL;
    TraceRingEntry* e = &g_ring[seq & (NUP_TRACE_RING_SIZE - 1u)];
    __atomic_store_n(&e->seq, 0ULL, __ATOMIC_RELAXED);
    e->slot_idx = slot_idx;
    e->caller_lr = clean_lr;
    e->x0 = x0;
    e->x1 = x1;
    e->x2 = x2;
    e->x3 = x3;
    e->timestamp = read_cntpct();
    __atomic_store_n(&e->seq, seq, __ATOMIC_RELEASE);

    return target;
}

static void fmt_trace_addr(u64 addr, char* out, size_t out_sz) {
    if (g_trace_mods) {
        for (u32 m = 0; m < g_trace_mods->count; m++) {
            const LoadedModule* mod = &g_trace_mods->mods[m];
            if (addr >= mod->nso_base && addr < mod->nso_base + mod->total_size) {
                snprintf(out, out_sz, "%s+0x%llx", mod->name,
                         (unsigned long long)(addr - mod->nso_base));
                return;
            }
        }
    }
    snprintf(out, out_sz, "0x%llx", (unsigned long long)addr);
}

void nupTraceDumpRecent(const char* reason, u32 max_entries) {
    if (!g_trace_enabled)
        return;
    const u64 cur_seq = __atomic_load_n(&g_ring_seq, __ATOMIC_ACQUIRE);
    if (max_entries > NUP_TRACE_RING_SIZE)
        max_entries = NUP_TRACE_RING_SIZE;
    const u64 count = cur_seq < max_entries ? cur_seq : (u64)max_entries;
    const u64 start_seq = cur_seq - count + 1ULL;

    nupLogf("=== [TRACE FLIGHT RECORDER: %s] total_calls=%llu dropped=%llu showing_last=%llu (slots=%u/%u ovf=%u) ===\n",
            reason ? reason : "dump",
            (unsigned long long)cur_seq, (unsigned long long)g_dropped_total,
            (unsigned long long)count, g_slot_count, NUP_TRACE_MAX_SLOTS, g_overflow_count);
    for (u64 s = start_seq; s <= cur_seq; s++) {
        const TraceRingEntry* e = &g_ring[s & (NUP_TRACE_RING_SIZE - 1u)];
        const u64 eseq = __atomic_load_n(&e->seq, __ATOMIC_ACQUIRE);
        if (eseq != s)
            continue;
        const u32 idx = e->slot_idx;
        if (idx >= g_slot_count)
            continue;
        char lr_s[64];
        fmt_trace_addr(e->caller_lr, lr_s, sizeof(lr_s));
        nupLogf("  #%llu [%s] %s (x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx) <- %s\n",
                (unsigned long long)s, g_slots[idx].mod_name, g_slots[idx].name,
                (unsigned long long)e->x0, (unsigned long long)e->x1,
                (unsigned long long)e->x2, (unsigned long long)e->x3, lr_s);
    }
    nupLogFlush();
}

void nupTracePollHeartbeat(u32 elapsed_ms, bool boot_phase) {
    if (!g_trace_enabled)
        return;

    const u64 cur_seq = __atomic_load_n(&g_ring_seq, __ATOMIC_ACQUIRE);

    // 1. Persistent boot checkpoint drain: during early boot, batch-persist recent
    // ring entries so even an uncatchable hardware fault leaves a trail on SD.
    if (cur_seq > g_last_drained_seq) {
        u64 start = g_last_drained_seq + 1ULL;
        if (cur_seq - g_last_drained_seq > NUP_TRACE_RING_SIZE) {
            const u64 lost = (cur_seq - g_last_drained_seq) - NUP_TRACE_RING_SIZE;
            g_dropped_total += lost;
            start = cur_seq - NUP_TRACE_RING_SIZE + 1ULL;
            nupLogBufferedf("[trace %ums] ring overflow: dropped %llu entries (total_dropped=%llu)\n",
                            elapsed_ms, (unsigned long long)lost, (unsigned long long)g_dropped_total);
        }
        if (boot_phase) {
            u32 emitted = 0;
            for (u64 s = start; s <= cur_seq && emitted < 64; s++) {
                const TraceRingEntry* e = &g_ring[s & (NUP_TRACE_RING_SIZE - 1u)];
                if (__atomic_load_n(&e->seq, __ATOMIC_ACQUIRE) != s)
                    continue;
                const u32 idx = e->slot_idx;
                if (idx >= g_slot_count)
                    continue;
                char lr_s[64];
                fmt_trace_addr(e->caller_lr, lr_s, sizeof(lr_s));
                nupLogBufferedf("[tr #%llu] [%s] %s (x0=0x%llx x1=0x%llx x2=0x%llx) <- %s\n",
                                (unsigned long long)s, g_slots[idx].mod_name, g_slots[idx].name,
                                (unsigned long long)e->x0, (unsigned long long)e->x1,
                                (unsigned long long)e->x2, lr_s);
                emitted++;
            }
        }
        g_last_drained_seq = cur_seq;
    }

    // 2. First-seen API discovery (steady-state summary without flooding)
    u32 logged_now = 0;
    for (u32 i = 0; i < g_slot_count && logged_now < 48; i++) {
        const u32 h = __atomic_load_n(&g_slots[i].hits, __ATOMIC_ACQUIRE);
        if (h > 0 && g_slots[i].logged == 0) {
            g_slots[i].logged = h;
            char lr_s[64];
            fmt_trace_addr(g_slots[i].first_lr, lr_s, sizeof(lr_s));
            nupLogBufferedf("[trace-api %ums] [%s] %s (hits=%u x0=0x%llx x1=0x%llx <- %s)\n",
                            elapsed_ms, g_slots[i].mod_name, g_slots[i].name, h,
                            (unsigned long long)g_slots[i].first_x0,
                            (unsigned long long)g_slots[i].first_x1, lr_s);
            logged_now++;
        }
    }

    // 3. Inactivity snapshot: if no new traced calls arrived for >= 2000ms, log a
    // snapshot (note: inactivity alone does not prove a deadlock).
    if (cur_seq == g_hb_last_seq && cur_seq > 0) {
        g_hb_inactive_ms += (boot_phase ? 100u : 1000u);
        if (g_hb_inactive_ms >= 2000u && !g_hb_snapshot_dumped) {
            g_hb_snapshot_dumped = true;
            nupTraceDumpRecent("INACTIVITY SNAPSHOT >=2s (no new traced calls; not necessarily a hang)", 32);
        }
    } else {
        g_hb_last_seq = cur_seq;
        g_hb_inactive_ms = 0;
        g_hb_snapshot_dumped = false;
    }
}
