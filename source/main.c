// SPDX-License-Identifier: MIT
#include <dirent.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <switch.h>
#include <kaihen.h>

#include "elf_loader.h"
#include "hooks.h"
#include "log.h"
#include "nup.h"
#include "trace.h"

#define MAX_NUP_ENTRIES 32

// Keep libnx's own heap compact (256 MiB: enough for NUP TOC + NSO staging)
// so ~5.8 GiB remains free for the launched game's heap and GPU/virtual memory.
size_t __nx_heap_size = 0x10000000;

alignas(16) u8 __nx_exception_stack[0x4000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);

typedef struct {
    char label[0x60];
    char path[0x400];
    u64 title_id;
    u32 exefs_count;
    bool is_raw;
} NupEntry;

static NupEntry g_entries[MAX_NUP_ENTRIES];
static int g_entry_count = 0;
static int g_cursor = 0;
static FsFileSystem g_sd = {};
static bool g_sd_open = false;
static NupArchive g_nup = {};
ModuleSet g_mods = {};

static void fmt_addr_mod(u64 addr, char* out, size_t sz) {
    // Strip Switch 2 PAC signature bits from return addresses
    addr &= (1ULL << 39) - 1;
    for (u32 i = 0; i < g_mods.count; i++) {
        const LoadedModule* m = &g_mods.mods[i];
        if (addr >= m->nso_base && addr < m->nso_base + m->total_size) {
            _snprintf_r(_impure_ptr, out, sz, "%s+0x%llx", m->name, (unsigned long long)(addr - m->nso_base));
            return;
        }
    }
    _snprintf_r(_impure_ptr, out, sz, "0x%llx", (unsigned long long)addr);
}

void __libnx_exception_handler(ThreadExceptionDump* ctx) {
    char pc_s[64], lr_s[64];
    fmt_addr_mod(ctx->pc.x, pc_s, sizeof(pc_s));
    fmt_addr_mod(ctx->lr.x, lr_s, sizeof(lr_s));
    nupLogf("!!! EXCEPTION: desc=0x%x pc=%s lr=%s sp=0x%llx far=0x%llx esr=0x%x\n",
            ctx->error_desc, pc_s, lr_s,
            (unsigned long long)ctx->sp.x,
            (unsigned long long)ctx->far.x,
            ctx->esr);
    nupLogf("  x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
            (unsigned long long)ctx->cpu_gprs[0].x,
            (unsigned long long)ctx->cpu_gprs[1].x,
            (unsigned long long)ctx->cpu_gprs[2].x,
            (unsigned long long)ctx->cpu_gprs[3].x);
    nupLogf("  x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
            (unsigned long long)ctx->cpu_gprs[4].x,
            (unsigned long long)ctx->cpu_gprs[5].x,
            (unsigned long long)ctx->cpu_gprs[6].x,
            (unsigned long long)ctx->cpu_gprs[7].x);
    nupLogClose();
}

static bool has_nup_ext(const char* name) {
    const size_t len = strlen(name);
    if (len < 5) return false;
    const char* ext = name + len - 4;
    return ext[0] == '.' &&
           (ext[1] == 'n' || ext[1] == 'N') &&
           (ext[2] == 'u' || ext[2] == 'U') &&
           (ext[3] == 'p' || ext[3] == 'P');
}

static bool already_listed(const char* path) {
    for (int i = 0; i < g_entry_count; i++) {
        if (strcmp(g_entries[i].path, path) == 0)
            return true;
    }
    return false;
}

static char g_skip_note[256] = {};

static void scan_dir(const char* dir_path) {
    DIR* dir = opendir(dir_path);
    if (!dir)
        return;
    struct dirent* item;
    while ((item = readdir(dir)) && g_entry_count < MAX_NUP_ENTRIES) {
        if (item->d_name[0] == '.')
            continue;
        char full[0x400];
        if (strcmp(dir_path, "/") == 0)
            snprintf(full, sizeof(full), "/%s", item->d_name);
        else
            snprintf(full, sizeof(full), "%s/%s", dir_path, item->d_name);
        if (already_listed(full))
            continue;

        u64 tid = 0;
        u32 exefs_cnt = 0;
        bool is_raw = false;
        if (has_nup_ext(item->d_name)) {
            if (!nupProbe(&g_sd, full, &tid, NULL, &exefs_cnt)) {
                snprintf(g_skip_note, sizeof(g_skip_note), "Skipped %.40s: %s",
                         item->d_name, nupLastProbeError());
                continue;
            }
        } else {
            if (!nupProbeRaw(&g_sd, full, &tid, NULL, &exefs_cnt))
                continue;
            is_raw = true;
        }
        NupEntry* e = &g_entries[g_entry_count++];
        memset(e, 0, sizeof(*e));
        snprintf(e->label, sizeof(e->label), "%.54s", item->d_name);
        snprintf(e->path, sizeof(e->path), "%s", full);
        e->title_id = tid;
        e->exefs_count = exefs_cnt;
        e->is_raw = is_raw;
    }
    closedir(dir);
}

static void scan_all(void) {
    g_entry_count = 0;
    g_skip_note[0] = '\0';
    static const char* const dirs[] = {
        "/switch/KaiDump/dumps", "/backups", "/games", "/nup", "/NUX", "/backups/nup", "/backups/NUX", "/"
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        scan_dir(dirs[i]);
    if (g_cursor >= g_entry_count)
        g_cursor = 0;
}

static void draw(const char* status) {
    consoleClear();
    printf("  kaiHEN NUP / Raw Game Loader (In-Process)\n");
    printf("  =========================================\n\n");
    if (g_entry_count == 0) {
        printf("  No .nup archives or unpacked game folders found.\n");
        printf("  Place .nup or <App Name>/game/exefs+romfs in /backups, /games, /nup, /NUX, or /.\n\n");
    } else {
        for (int i = 0; i < g_entry_count; i++) {
            const NupEntry* e = &g_entries[i];
            printf("  %s [%s] %016llx  %s (%u exefs)\n",
                   i == g_cursor ? ">" : " ",
                   e->is_raw ? "RAW" : "NUP",
                   (unsigned long long)e->title_id, e->label, e->exefs_count);
        }
        printf("\n");
    }
    printf("  Up/Down select   A Launch   Y Trace Launch   L Static Audit\n");
    printf("  X rescan         B/+ exit\n\n");
    if (status && status[0])
        printf("  %s\n", status);
    if (g_skip_note[0])
        printf("  [!] %s\n", g_skip_note);
    consoleUpdate(NULL);
}

static u64 g_abort_holder[8] = {};
static u64 g_sdk_abort_holder[8] = {};
static alignas(16) u8 g_sdk_ex_stack[0x4000];
static alignas(16) u8 g_sdk_ex_info[0x400];

static bool is_readable_addr(u64 addr, size_t len);

static void on_sdk_user_exception(void* info) {
    if (!info) {
        nupLogf("!!! SDK USER EXCEPTION: info=NULL\n");
        nupLogFlush();
        return;
    }
    // Dump raw header + registers defensively (nn::os::UserExceptionInfo layout
    // starts with u32 type, u32 pad, u64 r[29], fp, lr, sp, pc, pstate, afsr0, afsr1, esr, far).
    const u32* w = (const u32*)info;
    const u64* q = (const u64*)info;
    const u32 exc_type = w[0];
    const u64 fp = q[30];
    const u64 lr = q[31] & 0x0000ffffffffffffULL;
    const u64 sp = q[32];
    const u64 pc = q[33] & 0x0000ffffffffffffULL;
    const u32 esr = w[69];
    const u64 far = q[36];
    char pc_s[64], lr_s[64];
    fmt_addr_mod(pc, pc_s, sizeof(pc_s));
    fmt_addr_mod(lr, lr_s, sizeof(lr_s));
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    nupLogf("!!! SDK USER EXCEPTION: tid=%llu type=0x%x pc=%s lr=%s sp=0x%llx fp=0x%llx far=0x%llx esr=0x%x\n",
            (unsigned long long)tid, exc_type, pc_s, lr_s,
            (unsigned long long)sp, (unsigned long long)fp,
            (unsigned long long)far, esr);
    nupLogf("  x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
            (unsigned long long)q[1], (unsigned long long)q[2],
            (unsigned long long)q[3], (unsigned long long)q[4]);
    nupLogf("  x8=%016llx x9=%016llx x19=%016llx x20=%016llx\n",
            (unsigned long long)q[9], (unsigned long long)q[10],
            (unsigned long long)q[20], (unsigned long long)q[21]);
    // Walk FP chain from faulting thread
    u64 fp_addr = fp;
    for (int i = 0; i < 16 && fp_addr && (fp_addr & 7ULL) == 0; i++) {
        if (!is_readable_addr(fp_addr, 16)) break;
        const u64* fpp = (const u64*)(uintptr_t)fp_addr;
        u64 next_fp = fpp[0];
        u64 ret_lr = fpp[1] & 0x0000ffffffffffffULL;
        char bt_s[64];
        fmt_addr_mod(ret_lr, bt_s, sizeof(bt_s));
        u64 soff = 0;
        const char* sym = elfAddrToSymbol(&g_mods, ret_lr, &soff);
        if (sym)
            nupLogf("  ex_bt[%d] %016llx (%s) %s+0x%llx\n", i, (unsigned long long)ret_lr, bt_s, sym, (unsigned long long)soff);
        else
            nupLogf("  ex_bt[%d] %016llx (%s)\n", i, (unsigned long long)ret_lr, bt_s);
        if (!next_fp || next_fp <= fp_addr || (next_fp - fp_addr) > 0x100000ULL) break;
        fp_addr = next_fp;
    }
    nupTraceDumpRecent("SDK USER EXCEPTION", 64);
    nupLogFlush();
}

extern volatile u32 g_open_file_count;
extern volatile u32 g_post_aov_active;
extern volatile u64 g_aov_tid;
extern volatile u64 g_bad_reent_callers[8];
extern volatile u32 g_bad_reent_count;
static Thread g_hb_thread;
static alignas(0x1000) u8 g_hb_stack[0x4000];
static Handle g_main_thread_handle = INVALID_HANDLE;

#define MAX_TRACKED_WORKERS 64
typedef struct {
    void* thread_type;
    Handle handle;
    u64 tid;
    void* fn;
    char name[32];
} TrackedWorker;
static TrackedWorker g_workers[MAX_TRACKED_WORKERS] = {};
static volatile u32 g_worker_count = 0;

static bool is_readable_addr(u64 addr, size_t len);

void nupRecordWorkerThread(void* thread_type, void* fn) {
    if (!thread_type || g_worker_count >= MAX_TRACKED_WORKERS)
        return;
    const u32* words = (const u32*)thread_type;
    // sizeof(nn::os::ThreadType) in FE SDK is <= 0x1f8 (0x230401e218 - 0x230401e020)
    for (u32 i = 0; i < 0x1f0 / 4; i++) {
        u32 cand = words[i];
        if (cand == 0 || cand == INVALID_HANDLE)
            continue;
        u64 tid = 0;
        if (R_SUCCEEDED(svcGetThreadId(&tid, (Handle)cand)) && tid != 0) {
            u32 cur = __atomic_load_n(&g_worker_count, __ATOMIC_ACQUIRE);
            if (cur > MAX_TRACKED_WORKERS) cur = MAX_TRACKED_WORKERS;
            for (u32 j = 0; j < cur; j++) {
                if (g_workers[j].handle == (Handle)cand || g_workers[j].tid == tid)
                    return;
            }
            u32 idx = __atomic_fetch_add(&g_worker_count, 1, __ATOMIC_ACQ_REL);
            if (idx < MAX_TRACKED_WORKERS) {
                g_workers[idx].thread_type = thread_type;
                g_workers[idx].handle = (Handle)cand;
                g_workers[idx].tid = tid;
                g_workers[idx].fn = fn;
                g_workers[idx].name[0] = '\0';
            }
            return;
        }
    }
}

void nupRecordWorkerThreadName(void* thread_type, const char* name) {
    if (!thread_type || !name)
        return;
    u32 cnt = __atomic_load_n(&g_worker_count, __ATOMIC_ACQUIRE);
    if (cnt > MAX_TRACKED_WORKERS) cnt = MAX_TRACKED_WORKERS;
    for (u32 i = 0; i < cnt; i++) {
        if (g_workers[i].thread_type == thread_type) {
            size_t n = strlen(name);
            if (n >= sizeof(g_workers[i].name)) n = sizeof(g_workers[i].name) - 1;
            memcpy(g_workers[i].name, name, n);
            g_workers[i].name[n] = '\0';
            return;
        }
    }
}

static void heartbeat_thread_fn(void* arg) {
    (void)arg;
    u32 elapsed_ms = 0;
    if (nupTraceIsEnabled()) {
        // Early-boot checkpoint drain (every 100ms for the first 2s) so even raw
        // hardware faults that skip user exception handlers leave persisted traces.
        for (u32 step = 1; step <= 20; step++) {
            svcSleepThread(100000000ULL);
            elapsed_ms = step * 100u;
            nupTracePollHeartbeat(elapsed_ms, true);
            nupLogFlush();
            if ((step % 10u) == 0u) {
                u64 used = 0, sys_used = 0, sys_tot = 0, ns_used = 0, ns_tot = 0;
                Result urc = svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
                svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
                svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
                svcGetInfo(&ns_used, InfoType_UsedNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
                svcGetInfo(&ns_tot, InfoType_TotalNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
                nupLogf("[hb] %us used=0x%llx(rc=0x%x) ns=0x%llx/0x%llx sysres=0x%llx/0x%llx files=%u workers=%u reent=%u tr_seq=%llu drop=%llu\n",
                        elapsed_ms / 1000u, (unsigned long long)used, urc,
                        (unsigned long long)ns_used, (unsigned long long)ns_tot,
                        (unsigned long long)sys_used, (unsigned long long)sys_tot,
                        g_open_file_count, g_worker_count, g_bad_reent_count,
                        (unsigned long long)nupTraceTotalSeq(),
                        (unsigned long long)nupTraceDroppedCount());
            }
        }
    }
    const u32 start_sec = nupTraceIsEnabled() ? 3u : 1u;
    for (u32 t = start_sec; t <= 12; t++) {
        svcSleepThread(1000000000ULL);
        elapsed_ms = t * 1000u;
        nupTracePollHeartbeat(elapsed_ms, false);
        nupLogFlush();
        u64 used = 0, sys_used = 0, sys_tot = 0, ns_used = 0, ns_tot = 0;
        Result urc = svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&ns_used, InfoType_UsedNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&ns_tot, InfoType_TotalNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
        if (nupTraceIsEnabled()) {
            nupLogf("[hb] %us used=0x%llx(rc=0x%x) ns=0x%llx/0x%llx sysres=0x%llx/0x%llx files=%u workers=%u reent=%u tr_seq=%llu drop=%llu\n",
                    t, (unsigned long long)used, urc,
                    (unsigned long long)ns_used, (unsigned long long)ns_tot,
                    (unsigned long long)sys_used, (unsigned long long)sys_tot,
                    g_open_file_count, g_worker_count, g_bad_reent_count,
                    (unsigned long long)nupTraceTotalSeq(),
                    (unsigned long long)nupTraceDroppedCount());
        } else {
            nupLogf("[hb] %us used=0x%llx(rc=0x%x) ns=0x%llx/0x%llx sysres=0x%llx/0x%llx files=%u workers=%u reent=%u\n",
                    t, (unsigned long long)used, urc,
                    (unsigned long long)ns_used, (unsigned long long)ns_tot,
                    (unsigned long long)sys_used, (unsigned long long)sys_tot,
                    g_open_file_count, g_worker_count, g_bad_reent_count);
        }
    }
    u32 sec = 12;
    for (;;) {
        svcSleepThread(2000000000ULL);
        sec += 2;
        nupTracePollHeartbeat(sec * 1000u, false);
        nupLogFlush();
    }
}

static bool g_sdk_ex_registered = false;

static void register_sdk_exception_handler(void) {
    if (g_sdk_ex_registered)
        return;
    typedef void (*SetUserExFn)(void (*)(void*), void*, size_t, void*);
    const u64 fn = elfFindSymbol(&g_mods, "_ZN2nn2os23SetUserExceptionHandlerEPFvPNS0_17UserExceptionInfoEEPvmS2_");
    if (fn) {
        ((SetUserExFn)(uintptr_t)fn)(on_sdk_user_exception, g_sdk_ex_stack, sizeof(g_sdk_ex_stack), g_sdk_ex_info);
        g_sdk_ex_registered = true;
        nupLogf("[6/6] registered nn::os::SetUserExceptionHandler\n");
    } else {
        nupLogf("[6/6] SetUserExceptionHandler not found; scanning...\n");
        elfLogMatchingSymbols(&g_mods, "SetUserExceptionHandler");
    }
}

static bool is_readable_addr(u64 addr, size_t len) {
    if (addr < 0x10000ULL)
        return false;
    MemoryInfo mi = {};
    u32 pi = 0;
    if (R_FAILED(svcQueryMemory(&mi, &pi, addr)))
        return false;
    return (mi.perm & Perm_R) != 0 && (addr + len) <= (mi.addr + mi.size);
}

static void dump_hex_bytes(const char* label, u64 addr, size_t len) {
    if (!is_readable_addr(addr, len)) {
        nupLogf("  %s @ 0x%llx: <unreadable>\n", label, (unsigned long long)addr);
        return;
    }
    const u8* p = (const u8*)(uintptr_t)addr;
    for (size_t off = 0; off < len; off += 16) {
        char line[96];
        int pos = 0;
        for (size_t j = 0; j < 16 && off + j < len; j++) {
            static const char hx[] = "0123456789abcdef";
            line[pos++] = hx[p[off + j] >> 4];
            line[pos++] = hx[p[off + j] & 0xf];
            line[pos++] = ' ';
        }
        line[pos++] = '|';
        for (size_t j = 0; j < 16 && off + j < len; j++) {
            u8 c = p[off + j];
            line[pos++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        line[pos] = '\0';
        nupLogf("  %s+0x%02zx: %s\n", label, off, line);
    }
}

static void dump_abort_info(const char* tag, const void* info) {
    char lr_s[64];
    fmt_addr_mod((u64)(uintptr_t)__builtin_return_address(0), lr_s, sizeof(lr_s));
    nupLogf("!!! %s(info=%p) lr=%s\n", tag, info, lr_s);
    if (info) {
        const u64* q = (const u64*)info;
        for (int i = 0; i < 10; i++) {
            char sym_s[64];
            fmt_addr_mod(q[i], sym_s, sizeof(sym_s));
            nupLogf("  [%d] = 0x%016llx (%s)\n", i, (unsigned long long)q[i], sym_s);
        }
        for (int i = 0; i < 8; i++) {
            if (is_readable_addr(q[i], 4)) {
                const char* s = (const char*)(uintptr_t)q[i];
                if (s[0] >= 0x20 && s[0] < 0x7f && s[1] >= 0x20 && s[1] < 0x7f) {
                    nupLogf("  str[%d] = '%.120s'\n", i, s);
                }
            }
        }
        dump_hex_bytes("info[1]", q[1], 0x40);
        if (q[2] != q[1])
            dump_hex_bytes("info[2]", q[2], 0x20);
    }
    // Walk AArch64 frame pointer chain
    u64* fp = (u64*)__builtin_frame_address(0);
    for (int i = 0; i < 24 && fp; i++) {
        if (!is_readable_addr((u64)(uintptr_t)fp, 16))
            break;
        u64 lr = fp[1] & 0x0000ffffffffffffULL;
        u64* nx = (u64*)(uintptr_t)fp[0];
        char bt_s[64];
        fmt_addr_mod(lr, bt_s, sizeof(bt_s));
        u64 sym_off = 0;
        const char* sym = elfAddrToSymbol(&g_mods, lr, &sym_off);
        if (sym)
            nupLogf("  bt[%d] %016llx (%s) %s+0x%llx\n", i, (unsigned long long)lr, bt_s, sym, (unsigned long long)sym_off);
        else
            nupLogf("  bt[%d] %016llx (%s)\n", i, (unsigned long long)lr, bt_s);
        if (!nx || nx <= fp || (u64)(uintptr_t)nx - (u64)(uintptr_t)fp > 0x100000ULL)
            break;
        fp = nx;
    }
}

void nupLogBacktrace(const char* tag, u64 caller, u64 arg0, u64 arg1) {
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    char lr_s[64];
    fmt_addr_mod(caller, lr_s, sizeof(lr_s));
    u64 lr_off = 0;
    const char* lr_sym = elfAddrToSymbol(&g_mods, caller, &lr_off);
    nupLogf("!!! HOOKED %s tid=%llu caller=%s (%s+0x%llx) arg0=0x%llx arg1=0x%llx\n",
            tag, (unsigned long long)tid, lr_s, lr_sym ? lr_sym : "?",
            (unsigned long long)lr_off, (unsigned long long)arg0, (unsigned long long)arg1);
    u64* fp = (u64*)__builtin_frame_address(0);
    for (int i = 0; i < 20 && fp; i++) {
        if (!is_readable_addr((u64)(uintptr_t)fp, 16))
            break;
        u64 lr = fp[1] & 0x0000ffffffffffffULL;
        u64* nx = (u64*)(uintptr_t)fp[0];
        char bt_s[64];
        fmt_addr_mod(lr, bt_s, sizeof(bt_s));
        u64 sym_off = 0;
        const char* sym = elfAddrToSymbol(&g_mods, lr, &sym_off);
        if (sym)
            nupLogf("  bt[%d] %016llx (%s) %s+0x%llx\n", i, (unsigned long long)lr, bt_s, sym, (unsigned long long)sym_off);
        else
            nupLogf("  bt[%d] %016llx (%s)\n", i, (unsigned long long)lr, bt_s);
        if (!nx || nx <= fp || (u64)(uintptr_t)nx - (u64)(uintptr_t)fp > 0x100000ULL)
            break;
        fp = nx;
    }
    nupTraceDumpRecent(tag, 64);
    nupLogFlush();
}

static void on_abort_observer(const void* info) {
    dump_abort_info("AbortObserver", info);
    nupTraceDumpRecent("AbortObserver", 64);
}

static void on_sdk_abort_observer(const void* info) {
    dump_abort_info("SdkAbortObserver", info);
    nupTraceDumpRecent("SdkAbortObserver", 64);
}

static bool g_abort_observers_registered = false;

static void register_sdk_abort_observers(void) {
    if (g_abort_observers_registered)
        return;
    g_abort_observers_registered = true;
    typedef void (*InitObsFn)(void*, void (*)(const void*));
    typedef void (*RegObsFn)(void*);
    const u64 init_app = elfFindSymbol(&g_mods, "_ZN2nn4diag29InitializeAbortObserverHolderEPNS0_19AbortObserverHolderEPFvRKNS0_9AbortInfoEE");
    const u64 reg_app = elfFindSymbol(&g_mods, "_ZN2nn4diag21RegisterAbortObserverEPNS0_19AbortObserverHolderE");
    const u64 init_sdk = elfFindSymbol(&g_mods, "_ZN2nn4diag32InitializeSdkAbortObserverHolderEPNS0_22SdkAbortObserverHolderEPFvRKNS0_12SdkAbortInfoEE");
    const u64 reg_sdk = elfFindSymbol(&g_mods, "_ZN2nn4diag24RegisterSdkAbortObserverEPNS0_22SdkAbortObserverHolderE");
    bool any_missing = false;
    if (init_app && reg_app) {
        ((InitObsFn)(uintptr_t)init_app)(g_abort_holder, on_abort_observer);
        ((RegObsFn)(uintptr_t)reg_app)(g_abort_holder);
        nupLogf("[6/6] registered nn::diag::AbortObserver\n");
    } else {
        any_missing = true;
    }
    if (init_sdk && reg_sdk) {
        ((InitObsFn)(uintptr_t)init_sdk)(g_sdk_abort_holder, on_sdk_abort_observer);
        ((RegObsFn)(uintptr_t)reg_sdk)(g_sdk_abort_holder);
        nupLogf("[6/6] registered nn::diag::SdkAbortObserver\n");
    } else {
        any_missing = true;
    }
    if (any_missing) {
        nupLogf("[6/6] AbortObserver symbol(s) missing; scanning...\n");
        elfLogMatchingSymbols(&g_mods, "AbortObserver");
    }
}

void nupOnBeforeInitSdkModule(void) {
    register_sdk_exception_handler();
    register_sdk_abort_observers();
}

void nupOnBeforeNninitStartup(void) {
    register_sdk_exception_handler();
}

void nupOnBeforeNnMain(void) {
    register_sdk_exception_handler();
    register_sdk_abort_observers();
}

static void cb_notify_exception_ready(void) {
    nupLogf("[6/6] nn::init::Start -> notifyExceptionHandlerReady\n");
    register_sdk_exception_handler();
}

static void cb_call_initializers(void) {
    nupLogf("[6/6] nn::init::Start -> callInitializers\n");
    elfRunInitArrays(&g_mods, register_sdk_abort_observers);
    nupLogf("[6/6] callInitializers done -> entering nnMain\n");
}

static void cb_call_finalizers(void) {
    nupLogf("[6/6] nn::init::Start -> callFinalizers\n");
}

static void dump_latest_erpt(Handle hen_sm) {
    Service r = {};
    Result rc = smGetService(&r, "erpt:r");
    if (R_FAILED(rc) && hen_sm != INVALID_HANDLE) {
        const SmServiceName enc = smEncodeName("erpt:r");
        Service proxy = {};
        serviceCreate(&proxy, hen_sm);
        proxy.own_handle = 0;
        Handle h = INVALID_HANDLE;
        rc = serviceDispatchIn(&proxy, 1, enc,
            .out_handle_attrs = {SfOutHandleAttr_HipcMove},
            .out_handles = &h);
        if (R_SUCCEEDED(rc) && h != INVALID_HANDLE)
            serviceCreate(&r, h);
    }
    if (R_FAILED(rc)) {
        nupLogf("[erpt] erpt:r open failed: 0x%x\n", rc);
        return;
    }
    Service mgr = {};
    rc = serviceDispatch(&r, 1, .out_num_objects = 1, .out_objects = &mgr);
    if (R_FAILED(rc)) {
        nupLogf("[erpt] manager failed: 0x%x\n", rc);
        serviceClose(&r);
        return;
    }
    static u8 list[0x15E8];
    const u32 type = 2;
    memset(list, 0, sizeof(list));
    rc = serviceDispatchIn(&mgr, 0, type,
        .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
        .buffers = {{list, sizeof(list)}});
    if (R_FAILED(rc)) {
        nupLogf("[erpt] list failed: 0x%x\n", rc);
        serviceClose(&mgr);
        serviceClose(&r);
        return;
    }
    const u32 count = *(const u32*)list;
    nupLogf("[erpt] %u crash report(s) available\n", count);
    u32 chosen_k = 0;
    for (u32 k = 0; k < count && k < 10; k++) {
        Service rep = {};
        if (R_FAILED(serviceDispatch(&r, 0, .out_num_objects = 1, .out_objects = &rep)))
            break;
        struct { u8 id[20]; } in;
        memcpy(in.id, list + 8 + k * 0x70 + 4, 20);
        bool skip_bg = false;
        if (R_SUCCEEDED(serviceDispatchIn(&rep, 0, in))) {
            static u8 head[0x800];
            u32 got = 0;
            if (R_SUCCEEDED(serviceDispatchOut(&rep, 1, got,
                    .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                    .buffers = {{head, sizeof(head)}})) && got > 24) {
                for (u32 at = 0; at + 24 < got; at++) {
                    if (memcmp(head + at, "ErrorCode", 9) == 0 && (head[at + 9] & 0xE0) == 0xA0) {
                        u32 len = head[at + 9] & 31;
                        char code[32] = {};
                        memcpy(code, head + at + 10, len < 31 ? len : 31);
                        if (strncmp(code, "2155-", 5) == 0 || strncmp(code, "2110-", 5) == 0)
                            skip_bg = true;
                        break;
                    }
                }
            }
            serviceDispatch(&rep, 4);
        }
        serviceClose(&rep);
        if (!skip_bg) {
            chosen_k = k;
            break;
        }
    }
    if (count > 0) {
        Service rep = {};
        if (R_SUCCEEDED(serviceDispatch(&r, 0, .out_num_objects = 1, .out_objects = &rep))) {
            struct { u8 id[20]; } in;
            memcpy(in.id, list + 8 + chosen_k * 0x70 + 4, 20);
            if (R_SUCCEEDED(serviceDispatchIn(&rep, 0, in))) {
                static u8 buf[0x10000];
                fsFsDeleteFile(&g_sd, "/kaihen/last_erpt.bin");
                fsFsCreateFile(&g_sd, "/kaihen/last_erpt.bin", 0, 0);
                FsFile ef = {};
                const bool f_ok = R_SUCCEEDED(fsFsOpenFile(&g_sd, "/kaihen/last_erpt.bin",
                                                           FsOpenMode_Write | FsOpenMode_Append, &ef));
                s64 pos = 0;
                bool code_logged = false;
                for (u32 chunk = 0; chunk < 16; chunk++) {
                    u32 got = 0;
                    if (R_FAILED(serviceDispatchOut(&rep, 1, got,
                            .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                            .buffers = {{buf, sizeof(buf)}})) || got == 0)
                        break;
                    if (f_ok) {
                        fsFileWrite(&ef, pos, buf, got, FsWriteOption_Flush);
                        pos += got;
                    }
                    if (!code_logged) {
                        for (u32 at = 0; at + 24 < got; at++) {
                            if (memcmp(buf + at, "ErrorCode", 9) == 0 && (buf[at + 9] & 0xE0) == 0xA0) {
                                u32 len = buf[at + 9] & 31;
                                char code[32] = {};
                                memcpy(code, buf + at + 10, len < 31 ? len : 31);
                                nupLogf("[erpt] latest ErrorCode='%s' [idx=%u] (dumped %lld bytes to /kaihen/last_erpt.bin)\n",
                                        code, chosen_k, (long long)pos);
                                code_logged = true;
                                break;
                            }
                        }
                    }
                }
                if (f_ok) {
                    fsFileFlush(&ef);
                    fsFileClose(&ef);
                    fsFsCommit(&g_sd);
                }
                if (!code_logged)
                    nupLogf("[erpt] dumped %lld bytes [idx=%u] to /kaihen/last_erpt.bin\n", (long long)pos, chosen_k);
                serviceDispatch(&rep, 4);
            }
            serviceClose(&rep);
        }
    }
    serviceClose(&mgr);
    serviceClose(&r);
}

static void collect_runtime_caps(NupRuntimeCapabilities* caps, NupArchive* nup,
                                 const NupFileInfo* exefs, u32 exefs_count,
                                 const ModuleSet* mods, u64 target_tid) {
    memset(caps, 0, sizeof(*caps));
    caps->target_tid = target_tid;
    caps->target_is_switch1 = ((target_tid >> 56) == 0x01);

    svcGetInfo(&caps->donor_pid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_mem_used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_mem_total, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_sysres_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_sysres_total, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);

    caps->donor_is_switch1 = ((caps->donor_pid >> 56) == 0x01);
    caps->vam_capable = (caps->donor_sysres_total > 0);
    caps->sysres_sufficient = true;

    // Parse target main.npdm (META header)
    const NupFileInfo* npdm_fi = NULL;
    for (u32 i = 0; i < exefs_count; i++) {
        if (strcmp(exefs[i].name, "main.npdm") == 0) {
            npdm_fi = &exefs[i];
            break;
        }
    }
    if (npdm_fi) {
        u8 meta[0x80];
        memset(meta, 0, sizeof(meta));
        const size_t rlen = npdm_fi->size < sizeof(meta) ? (size_t)npdm_fi->size : sizeof(meta);
        if (R_SUCCEEDED(nupReadExefs(nup, npdm_fi, 0, meta, rlen)) &&
            rlen >= 0x30 && memcmp(meta, "META", 4) == 0) {
            caps->target_npdm_valid = true;
            caps->target_npdm_flags = meta[0x0c];
            caps->target_main_prio = meta[0x0e];
            caps->target_main_core = meta[0x0f];
            memcpy(&caps->target_sysres_required, meta + 0x14, 4);
            memcpy(&caps->target_main_stack_size, meta + 0x1c, 4);
            memcpy(caps->target_proc_name, meta + 0x20, 16);
            caps->target_proc_name[16] = '\0';
            caps->is_64bit = (caps->target_npdm_flags & 1) != 0;
            caps->sysres_sufficient = (caps->donor_sysres_total >= (u64)caps->target_sysres_required);
        }
    }

    if (mods) {
        for (u32 m = 0; m < mods->count; m++) {
            const LoadedModule* mod = &mods->mods[m];
            if (strcmp(mod->name, "compat1") == 0) caps->has_compat1 = true;
            if (strcmp(mod->name, "compat2") == 0) caps->has_compat2 = true;
            const u32 fw = mod->nso_base ? *(const u32*)(uintptr_t)mod->nso_base : 0;
            if (fw == 1 && mod->module_object_off) caps->has_modobj20 = true;
        }
        const u64 s5 = elfFindSymbolSkipCompat1(mods, "_ZN2nn4init5StartEmmPFvvES2_S2_");
        const u64 s4 = elfFindSymbolSkipCompat1(mods, "_ZN2nn4init5StartEmmPFvvES2_");
        snprintf(caps->entry_kind, sizeof(caps->entry_kind), "%s",
                 s5 ? "5arg" : (s4 ? "4arg" : "manual"));
    }
}

static void log_runtime_caps(const NupRuntimeCapabilities* c) {
    nupLogBufferedf("\n--- CAPABILITY & RESOURCE COMPATIBILITY ---\n");
    nupLogBufferedf("  Donor ProgramId:           %016llx (%s)\n",
                    (unsigned long long)c->donor_pid,
                    c->donor_is_switch1 ? "Switch 1 donor" : "Switch 2 donor");
    nupLogBufferedf("  Donor Memory:              used=0x%llx / total=0x%llx\n",
                    (unsigned long long)c->donor_mem_used, (unsigned long long)c->donor_mem_total);
    nupLogBufferedf("  VAM capability:            %s\n", c->vam_capable ? "ENABLED" : "DISABLED");
    nupLogBufferedf("  System resource capacity:  %llu MiB (0x%llx, used=0x%llx)\n",
                    (unsigned long long)(c->donor_sysres_total / (1024ULL * 1024ULL)),
                    (unsigned long long)c->donor_sysres_total,
                    (unsigned long long)c->donor_sysres_used);
    if (c->target_npdm_valid) {
        nupLogBufferedf("  Target main.npdm:          name='%s' flags=0x%02x (64bit=%d, addrspace=%u) prio=%u core=%u stack=0x%x\n",
                        c->target_proc_name, c->target_npdm_flags, c->is_64bit ? 1 : 0,
                        (c->target_npdm_flags >> 1) & 7, c->target_main_prio, c->target_main_core,
                        c->target_main_stack_size);
        nupLogBufferedf("  Target requirement:        %u MiB (0x%x)\n",
                        c->target_sysres_required / (1024u * 1024u), c->target_sysres_required);
        if (c->sysres_sufficient) {
            nupLogBufferedf("  Resource requirement:      SUFFICIENT\n");
        } else {
            const u64 short_bytes = (u64)c->target_sysres_required - c->donor_sysres_total;
            nupLogBufferedf("  Resource requirement:      INSUFFICIENT (short by %llu MiB / 0x%llx)\n",
                            (unsigned long long)(short_bytes / (1024ULL * 1024ULL)),
                            (unsigned long long)short_bytes);
        }
    } else {
        nupLogBufferedf("  Target main.npdm:          NOT FOUND / UNREADABLE\n");
    }
    const char* cpack = (c->has_compat1 && c->has_compat2) ? "ATTACHED (compat1+compat2)"
                      : (!c->target_is_switch1 ? "NOT NEEDED (Switch 2 ABI target)"
                      : "MISSING (Switch 1 ABI target requires Switch 1 donor)");
    nupLogBufferedf("  CompatibilityPack:         %s\n", cpack);
}

static Result audit_nup(const NupEntry* entry, char* out_status, size_t out_status_sz) {
    consoleClear();
    printf("  Static Audit: %s\n", entry->label);
    printf("  Title ID: %016llx\n\n", (unsigned long long)entry->title_id);
    consoleUpdate(NULL);

    char audit_path[0x80];
    snprintf(audit_path, sizeof(audit_path), "/kaihen/audits/%016llx.txt",
             (unsigned long long)entry->title_id);
    nupLogInit(&g_sd, audit_path);
    nupLogf("=== nup-loader [build=0325-cap2] STATIC AUDIT: %s (tid=%016llx, %s) ===\n",
            entry->path, (unsigned long long)entry->title_id,
            entry->is_raw ? "RAW" : "NUP");

    NupFileInfo exefs[NUP_MAX_EXEFS_FILES];
    u32 exefs_count = 0;
    Result rc = 0;
    if (entry->is_raw) {
        if (!nupProbeRaw(&g_sd, entry->path, NULL, exefs, &exefs_count)) {
            nupLogf("[!] nupProbeRaw failed\n");
            nupLogClose();
            snprintf(out_status, out_status_sz, "audit failed: probe raw");
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
        rc = nupOpenRaw(&g_nup, &g_sd, entry->path);
    } else {
        if (!nupProbe(&g_sd, entry->path, NULL, exefs, &exefs_count)) {
            nupLogf("[!] nupProbe failed\n");
            nupLogClose();
            snprintf(out_status, out_status_sz, "audit failed: probe nup");
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
        rc = nupOpenFull(&g_nup, &g_sd, entry->path);
    }
    if (R_FAILED(rc)) {
        nupLogf("[!] open failed: 0x%x\n", rc);
        nupLogClose();
        snprintf(out_status, out_status_sz, "audit open failed: 0x%x", rc);
        return rc;
    }

    const u64 sel_tid = g_nup.title_id ? g_nup.title_id : entry->title_id;

    ModuleSet audit_mods = {};
    rc = elfLoadNupModulesForAudit(&audit_mods, &g_nup, exefs, exefs_count);
    if (R_FAILED(rc)) {
        nupLogf("[!] elfLoadNupModulesForAudit failed: 0x%x\n", rc);
        nupClose(&g_nup);
        nupLogClose();
        snprintf(out_status, out_status_sz, "audit read NSO failed: 0x%x", rc);
        return rc;
    }

    elfAttachSwitch1Compat(&audit_mods, sel_tid);
    NupRuntimeCapabilities caps = {};
    collect_runtime_caps(&caps, &g_nup, exefs, exefs_count, &audit_mods, sel_tid);
    log_runtime_caps(&caps);

    printf("  Auditing %u modules...\n", audit_mods.count);
    consoleUpdate(NULL);

    ElfAuditSummary sum = {};
    elfRunStaticAudit(&audit_mods, &caps, hooksResolve, &sum);

    elfUnloadAuditModules(&audit_mods);
    nupClose(&g_nup);
    nupLogClose();

    snprintf(out_status, out_status_sz,
             "Audit -> %s (m=%u %s unres=%u hk=%u tr=%u/%u sysres=%s)",
             audit_path, sum.module_count, sum.entry_kind,
             sum.unresolved_count, sum.hooked_count,
             sum.trace_need_tramp, NUP_TRACE_MAX_SLOTS,
             caps.sysres_sufficient ? "OK" : "LOW");
    return 0;
}

static Result launch_nup(const NupEntry* entry, bool headless, bool trace_mode) {
    g_abort_observers_registered = false;
    g_sdk_ex_registered = false;
    g_worker_count = 0;
    nupTraceReset(trace_mode);

    char log_path[0x80];
    if (trace_mode) {
        snprintf(log_path, sizeof(log_path), "/kaihen/traces/%016llx.log",
                 (unsigned long long)entry->title_id);
    } else {
        snprintf(log_path, sizeof(log_path), "/kaihen/nup-loader.log");
    }
    nupLogInit(&g_sd, log_path);
    nupLogf("=== nup-loader [build=0325-cap2] (%s%s): %s (tid=%016llx) ===\n",
            headless ? "headless" : "ui",
            trace_mode ? "+TRACE" : "",
            entry->path, (unsigned long long)entry->title_id);

    if (!headless) {
        consoleClear();
        printf("  %s %s\n", trace_mode ? "TRACE Launching" : "Launching", entry->label);
        printf("  Title ID: %016llx\n", (unsigned long long)entry->title_id);
        printf("  Log: %s\n\n", log_path);
        consoleUpdate(NULL);
    }

    Handle hen_sm = INVALID_HANDLE;
    Service ro = {}, hen = {};
    if (R_SUCCEEDED(kaihenGetRoSession(&ro)) &&
        R_SUCCEEDED(kaihenOpenHomebrewSession(&ro, &hen))) {
        henGetServiceManager(&hen, &hen_sm);
        serviceClose(&hen);
    }
    nupLogf("[1/6] hen_sm=%s\n", hen_sm != INVALID_HANDLE ? "ready" : "unavailable");
    dump_latest_erpt(hen_sm);
    if (!headless) {
        printf("  [1/6] HEN SM proxy: %s\n", hen_sm != INVALID_HANDLE ? "ready" : "unavailable");
        consoleUpdate(NULL);
    }

    Result rc = ldrRoInitialize();
    if (R_FAILED(rc)) {
        nupLogf("[!] ldrRoInitialize failed: 0x%x\n", rc);
        return rc;
    }

    NupFileInfo exefs[NUP_MAX_EXEFS_FILES];
    u32 exefs_count = 0;
    if (entry->is_raw) {
        if (!nupProbeRaw(&g_sd, entry->path, NULL, exefs, &exefs_count)) {
            nupLogf("[!] nupProbeRaw failed\n");
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
        if (!headless) { printf("  [2/6] Opening raw folder %s...\n", entry->path); consoleUpdate(NULL); }
        rc = nupOpenRaw(&g_nup, &g_sd, entry->path);
        if (R_FAILED(rc)) {
            nupLogf("[!] nupOpenRaw failed: 0x%x\n", rc);
            return rc;
        }
        nupLogf("[2/6] RAW opened: %s exefs=%u romfs=%d\n",
                entry->path, exefs_count, g_nup.has_romfs ? 1 : 0);
    } else {
        if (!nupProbe(&g_sd, entry->path, NULL, exefs, &exefs_count)) {
            nupLogf("[!] nupProbe failed\n");
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        }
        if (!headless) { printf("  [2/6] Loading NUP TOC into RAM...\n"); consoleUpdate(NULL); }
        rc = nupOpenFull(&g_nup, &g_sd, entry->path);
        if (R_FAILED(rc)) {
            nupLogf("[!] nupOpenFull failed: 0x%x\n", rc);
            return rc;
        }
        nupLogf("[2/6] TOC loaded: parts=%u dirs=%llu files=%llu romfs_layers=%u sel_tid=%016llx\n",
                g_nup.part_count,
                (unsigned long long)g_nup.dir_count,
                (unsigned long long)g_nup.file_count,
                g_nup.romfs_layer_count,
                (unsigned long long)g_nup.title_id);
        for (u32 pi = 0; pi < g_nup.part_count && pi < 16; pi++) {
            const NupPartEntry* pe = &g_nup.parts[pi];
            nupLogf("  part[%u]: tid=%016llx kind=%u flags=0x%x ver=%u exefs=%u romfs=%u\n",
                    pi, (unsigned long long)pe->title_id, pe->kind, pe->flags,
                    pe->version, pe->exefs_dir_idx, pe->romfs_dir_idx);
        }
    }

    if (!headless) { printf("  [3/6] Mapping ExeFS NSOs via ldr:ro...\n"); consoleUpdate(NULL); }
    rc = elfLoadNupModules(&g_mods, &g_nup, exefs, exefs_count);
    if (R_FAILED(rc)) {
        nupLogf("[!] elfLoadNupModules failed: 0x%x\n", rc);
        nupClose(&g_nup);
        return rc;
    }

    const u64 sel_tid = g_nup.title_id ? g_nup.title_id : entry->title_id;
    elfAttachSwitch1Compat(&g_mods, sel_tid);
    NupRuntimeCapabilities caps = {};
    collect_runtime_caps(&caps, &g_nup, exefs, exefs_count, &g_mods, sel_tid);
    if (trace_mode) {
        if (!headless) { printf("  [4/6] Running capability + hook/capacity audit...\n"); consoleUpdate(NULL); }
        log_runtime_caps(&caps);
        elfRunStaticAudit(&g_mods, &caps, hooksResolve, NULL);
    }
    if (!headless) { printf("  [4/6] Relocating %u modules & applying compatibility providers...\n", g_mods.count); consoleUpdate(NULL); }
    hooksInit(&g_nup, &g_sd, &caps, hen_sm);
    u32 unresolved = 0;
    rc = elfRelocateAll(&g_mods, hooksResolve, &unresolved);
    if (R_FAILED(rc)) {
        nupLogf("[!] elfRelocateAll failed: 0x%x\n", rc);
        return rc;
    }
    u64 init_start_addr = elfFindSymbol(&g_mods, "_ZN2nn4init5StartEmmPFvvES2_S2_");
    bool init_start_4arg = false;
    if (!init_start_addr) {
        init_start_addr = elfFindSymbol(&g_mods, "_ZN2nn4init5StartEmmPFvvES2_");
        if (init_start_addr)
            init_start_4arg = true;
    }
    const u64 startup_addr = elfFindSymbol(&g_mods, "nninitStartup");
    const u64 main_addr = elfFindSymbol(&g_mods, "nnMain");
    nupLogf("[4/6] reloc done: unresolved=%u compat=%d nn::init::Start=%016llx(%s) nninitStartup=%016llx nnMain=%016llx\n",
            unresolved, g_mods.has_compat ? 1 : 0, (unsigned long long)init_start_addr,
            init_start_addr ? (init_start_4arg ? "4arg" : "5arg") : "manual",
            (unsigned long long)startup_addr, (unsigned long long)main_addr);
    if (!init_start_addr && !main_addr) {
        nupLogf("[!] entry symbol not found!\n");
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }

    if (!headless) {
        printf("  [5/6] Tearing down loader UI/applet & handing off...\n");
        consoleUpdate(NULL);
        nupLogf("[5/6] tearing down console/fsdev/hid/applet\n");
        svcSleepThread(300000000ULL);
        consoleExit(NULL);
        fsdevUnmountDevice("sdmc");
        hidExit();
    } else {
        nupLogf("[5/6] headless handoff (console/vi/nv/hid never initialized), closing applet\n");
    }
    // When CompatibilityPack (compat2) is NOT attached (e.g. testing Switch 1 ABI on a Switch 2 donor),
    // pre-open GSV nvservices; when compat2 IS attached, leave GSV untouched so compat2 initializes it.
    if (caps.target_is_switch1 && !caps.has_compat2) {
        Result gsv_rc = gsvInitialize();
        Handle nv_h = INVALID_HANDLE;
        Result nv_rc = R_SUCCEEDED(gsv_rc) ? gsvOpenNvServices(&nv_h) : gsv_rc;
        nupLogf("[5/6] Switch1 GSV nvservices: gsv=0x%x nv=0x%x h=0x%x\n", gsv_rc, nv_rc, nv_h);
        if (R_SUCCEEDED(nv_rc) && nv_h != INVALID_HANDLE)
            hooksSetNvHandle(nv_h);
        // gsvInitialize() calls appletInitialize(), incrementing the applet refcount.
        // Drop that extra ref so the appletExit() below closes libnx's appletOE session cleanly!
        if (R_SUCCEEDED(gsv_rc))
            appletExit();
    }

    appletExit();

    // Log host process identity & thread/memory capabilities before handoff
    {
        u64 cm = 0, pm = 0, used = 0, tot = 0, pid = 0, sys_tot = 0, sys_used = 0, is_app = 0;
        u64 sr_a = 0, sr_s = 0, al_a = 0, al_s = 0;
        svcGetInfo(&cm, InfoType_CoreMask, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&pm, InfoType_PriorityMask, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&tot, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&pid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&is_app, InfoType_IsApplication, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sr_a, InfoType_StackRegionAddress, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sr_s, InfoType_StackRegionSize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&al_a, InfoType_AliasRegionAddress, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&al_s, InfoType_AliasRegionSize, CUR_PROCESS_HANDLE, 0);
        nupLogf("[5/6] host pid=%016llx is_app=%llu cm=0x%llx pm=0x%llx mem=0x%llx/0x%llx sysres=0x%llx/0x%llx\n",
                (unsigned long long)pid, (unsigned long long)is_app,
                (unsigned long long)cm, (unsigned long long)pm,
                (unsigned long long)used, (unsigned long long)tot,
                (unsigned long long)sys_used, (unsigned long long)sys_tot);
        nupLogf("[5/6] regions stack=[0x%llx+0x%llx] alias=[0x%llx+0x%llx]\n",
                (unsigned long long)sr_a, (unsigned long long)sr_s,
                (unsigned long long)al_a, (unsigned long long)al_s);
    }

    // Start unconditional liveness heartbeat before heap shrink so we can
    // distinguish a hang/deadlock from a process crash or console freeze.
    {
        g_main_thread_handle = envGetMainThreadHandle();
        Result hb_rc = threadCreate(&g_hb_thread, heartbeat_thread_fn, NULL,
                                    g_hb_stack, sizeof(g_hb_stack), 0x20, -2);
        if (R_SUCCEEDED(hb_rc))
            hb_rc = threadStart(&g_hb_thread);
        nupLogf("[5/6] heartbeat thread start -> 0x%x\n", hb_rc);
    }

    // Release hbloader's huge heap override back to the OS so the game's
    // virtual-address-memory / AllocateMemoryPages calls have ~8.6 GiB free!
    // Note: in libnx, sbrk(0) returns fake_heap_end (the entire 8.9 GiB override),
    // so we compute the real high-water mark from our own allocations + non-Heap blocks.
    {
        u64 heap_base = 0, heap_region_sz = 0, tot_before = 0, used_before = 0;
        svcGetInfo(&heap_base, InfoType_HeapRegionAddress, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&heap_region_sz, InfoType_HeapRegionSize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&tot_before, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&used_before, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);

        u64 high = heap_base;
        if (g_nup.toc_buf) {
            const u64 toc_end = (u64)(uintptr_t)g_nup.toc_buf + g_nup.toc_size;
            if (toc_end > high) high = toc_end;
        }
        for (u32 i = 0; i < g_mods.count; i++) {
            if (g_mods.mods[i].src_buf) {
                const u64 e = (u64)(uintptr_t)g_mods.mods[i].src_buf + g_mods.mods[i].total_size;
                if (e > high) high = e;
            }
            if (g_mods.mods[i].bss_buf) {
                const u64 e = (u64)(uintptr_t)g_mods.mods[i].bss_buf + g_mods.mods[i].total_size;
                if (e > high) high = e;
            }
        }
        // Also scan heap region for any non-Heap (e.g. ldr:ro Inaccessible) blocks.
        u64 cursor = heap_base;
        const u64 heap_limit = heap_base + heap_region_sz;
        for (int i = 0; i < 256 && cursor < heap_limit; i++) {
            MemoryInfo mi = {};
            u32 pi = 0;
            if (R_FAILED(svcQueryMemory(&mi, &pi, cursor)) || !mi.size)
                break;
            if (mi.type == MemType_Unmapped)
                break;
            if (mi.type != MemType_Heap && mi.addr + mi.size > high)
                high = mi.addr + mi.size;
            cursor = mi.addr + mi.size;
        }
        u64 keep = 0x10000000ull;
        if (high > heap_base) {
            keep = ((high - heap_base) + 0x400000ull + 0x1fffffull) & ~0x1fffffull;
        }
        void* shrunk_base = NULL;
        const Result shrink_rc = svcSetHeapSize(&shrunk_base, (size_t)keep);
        u64 used_after = 0;
        svcGetInfo(&used_after, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
        nupLogf("[5/6] heap shrink: heap_base=0x%llx high=0x%llx keep=0x%llx rc=0x%x used: 0x%llx -> 0x%llx (total=0x%llx)\n",
                (unsigned long long)heap_base, (unsigned long long)high,
                (unsigned long long)keep, shrink_rc,
                (unsigned long long)used_before, (unsigned long long)used_after,
                (unsigned long long)tot_before);
    }

    const Handle main_thread = envGetMainThreadHandle();
    if (init_start_addr) {
        nupLogf("[6/6] calling nn::init::Start(%s, thread=0x%x) @ %016llx\n",
                init_start_4arg ? "4arg" : "5arg",
                main_thread, (unsigned long long)init_start_addr);
        if (init_start_4arg) {
            typedef void (*NnInitStart4Fn)(u64, u64, void (*)(void), void (*)(void));
            ((NnInitStart4Fn)(uintptr_t)init_start_addr)(
                (u64)main_thread, 0,
                cb_notify_exception_ready, cb_call_initializers);
        } else {
            typedef void (*NnInitStart5Fn)(u64, u64, void (*)(void), void (*)(void), void (*)(void));
            ((NnInitStart5Fn)(uintptr_t)init_start_addr)(
                (u64)main_thread, 0,
                cb_notify_exception_ready, cb_call_initializers, cb_call_finalizers);
        }
        nupLogf("[6/6] nn::init::Start returned\n");
    } else {
        nupLogf("[6/6] manual Switch 1 SDK startup sequence (thread=0x%x)\n", main_thread);
        u64 fn = 0;
        if ((fn = elfFindSymbolSkipCompat1(&g_mods, "__nnDetailInitLibc0"))) {
            nupLogf("[6/6] calling __nnDetailInitLibc0 @ %016llx\n", (unsigned long long)fn);
            ((void (*)(void))(uintptr_t)fn)();
        }
        if ((fn = elfFindSymbolSkipCompat1(&g_mods, "nnosInitialize"))) {
            nupLogf("[6/6] calling nnosInitialize @ %016llx\n", (unsigned long long)fn);
            ((void (*)(u32, void*))(uintptr_t)fn)(main_thread, NULL);
        }
        register_sdk_exception_handler();
        elfInitSwitch1CompatParams(&g_mods);
        elfRunCompatInitArrays(&g_mods);
        hooksMarkCompatHeapEnd();
        if ((fn = elfFindSymbolSkipCompat1(&g_mods, "__nnDetailInitLibc1")) ||
            (fn = elfFindSymbolSkipCompat1(&g_mods, "_init_libc1"))) {
            nupLogf("[6/6] calling InitLibc1 @ %016llx\n", (unsigned long long)fn);
            ((void (*)(void))(uintptr_t)fn)();
        }
        if ((fn = elfFindSymbolSkipCompat1(&g_mods, "nndiagStartup"))) {
            nupLogf("[6/6] calling nndiagStartup @ %016llx\n", (unsigned long long)fn);
            ((void (*)(void))(uintptr_t)fn)();
        }
        if ((fn = elfFindSymbolSkipCompat1(&g_mods, "nninitInitializeSdkModule"))) {
            nupLogf("[6/6] calling nninitInitializeSdkModule @ %016llx\n", (unsigned long long)fn);
            ((void (*)(void))(uintptr_t)fn)();
        }
        register_sdk_exception_handler();
        if (startup_addr) {
            nupLogf("[6/6] calling nninitStartup @ %016llx\n", (unsigned long long)startup_addr);
            ((void (*)(void))(uintptr_t)startup_addr)();
        }
        if ((fn = elfFindSymbolSkipCompat1(&g_mods, "__nnDetailInitLibc2")) ||
            (fn = elfFindSymbolSkipCompat1(&g_mods, "_init_libc2"))) {
            nupLogf("[6/6] calling InitLibc2 @ %016llx\n", (unsigned long long)fn);
            ((void (*)(void))(uintptr_t)fn)();
        }
        elfRunInitArrays(&g_mods, register_sdk_abort_observers);
        nupLogf("[6/6] calling nnMain @ %016llx\n", (unsigned long long)main_addr);
        ((void (*)(void))(uintptr_t)main_addr)();
    }
    nupLogClose();
    return 0;
}

static bool try_read_autolaunch(NupEntry* out, bool* out_trace) {
    if (out_trace) *out_trace = false;
    if (!g_sd_open) return false;
    FsFile f = {};
    if (R_FAILED(nupRawFsOpenFile(&g_sd, "/kaihen/autolaunch.txt", FsOpenMode_Read, &f)))
        return false;
    char buf[0x400];
    memset(buf, 0, sizeof(buf));
    u64 got = 0;
    nupRawFileRead(&f, 0, buf, sizeof(buf) - 1, &got);
    serviceClose(&f.s);
    if (!got) return false;
    // Take first non-empty line and trim whitespace
    char* p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    char* end = p;
    while (*end && *end != '\r' && *end != '\n') end++;
    while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '/')) end--;
    *end = '\0';
    if (strncmp(p, "trace:", 6) == 0) {
        if (out_trace) *out_trace = true;
        p += 6;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (!p[0]) return false;

    memset(out, 0, sizeof(*out));
    snprintf(out->path, sizeof(out->path), "%s", p);
    snprintf(out->label, sizeof(out->label), "%.54s", p);
    if (has_nup_ext(p)) {
        if (!nupProbe(&g_sd, p, &out->title_id, NULL, &out->exefs_count))
            return false;
        out->is_raw = false;
        return true;
    }
    if (!nupProbeRaw(&g_sd, p, &out->title_id, NULL, &out->exefs_count))
        return false;
    out->is_raw = true;
    return true;
}

int main(void) {
    if (R_SUCCEEDED(fsOpenSdCardFileSystem(&g_sd)))
        g_sd_open = true;

    // Headless auto-launch if /kaihen/autolaunch.txt exists:
    // never touches consoleInit / vi2 / nv / hid before handing off to the game!
    NupEntry auto_entry = {};
    bool auto_trace = false;
    if (try_read_autolaunch(&auto_entry, &auto_trace)) {
        launch_nup(&auto_entry, true, auto_trace);
        if (g_sd_open) fsFsClose(&g_sd);
        return 0;
    }

    consoleInit(NULL);
    fsdevMountSdmc();

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    char status[0x100] = {};
    if (g_sd_open)
        scan_all();
    else
        snprintf(status, sizeof(status), "failed to open SD filesystem");
    draw(status);

    while (appletMainLoop()) {
        padUpdate(&pad);
        const u64 down = padGetButtonsDown(&pad);

        if (down & (HidNpadButton_Plus | HidNpadButton_B))
            break;

        if (down & (HidNpadButton_Up | HidNpadButton_Down)) {
            if (g_entry_count > 0) {
                g_cursor += (down & HidNpadButton_Down) ? 1 : -1;
                if (g_cursor < 0) g_cursor = g_entry_count - 1;
                if (g_cursor >= g_entry_count) g_cursor = 0;
            }
            draw(status);
            continue;
        }

        if (down & HidNpadButton_X) {
            scan_all();
            snprintf(status, sizeof(status), "rescanned (%d found)", g_entry_count);
            draw(status);
            continue;
        }

        if ((down & HidNpadButton_L) && g_entry_count > 0) {
            audit_nup(&g_entries[g_cursor], status, sizeof(status));
            draw(status);
            continue;
        }

        if ((down & (HidNpadButton_A | HidNpadButton_Y)) && g_entry_count > 0) {
            const bool trace_mode = (down & HidNpadButton_Y) != 0;
            const Result rc = launch_nup(&g_entries[g_cursor], false, trace_mode);
            if (R_FAILED(rc)) {
                snprintf(status, sizeof(status), "launch failed: 0x%x (press any key)", rc);
                printf("\n  %s\n", status);
                consoleUpdate(NULL);
                while (appletMainLoop()) {
                    padUpdate(&pad);
                    if (padGetButtonsDown(&pad))
                        break;
                    svcSleepThread(16000000ULL);
                }
                draw(status);
            }
        }
    }

    if (g_sd_open)
        fsFsClose(&g_sd);
    fsdevUnmountDevice("sdmc");
    consoleExit(NULL);
    return 0;
}
