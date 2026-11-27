// SPDX-License-Identifier: MIT
#include "diag.h"
#include "elf_loader.h"
#include "log.h"
#include "trace.h"

#include <stdalign.h>
#include <stdio.h>
#include <string.h>

extern ModuleSet g_mods;
extern volatile u32 g_open_file_count;
extern volatile u32 g_post_aov_active;
extern volatile u64 g_aov_tid;
extern volatile u64 g_bad_reent_callers[8];
extern volatile u32 g_bad_reent_count;

alignas(16) u8 __nx_exception_stack[0x4000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);
u32 __nx_exception_ignoredebug = 1;

static u64 g_abort_holder[8] = {};
static u64 g_sdk_abort_holder[8] = {};
static alignas(16) u8 g_sdk_ex_stack[0x4000];
static alignas(16) u8 g_sdk_ex_info[0x400];
static bool g_sdk_ex_registered = false;
static bool g_abort_observers_registered = false;

static Thread g_hb_thread;
static alignas(0x1000) u8 g_hb_stack[0x4000];
static Handle g_main_thread_handle = INVALID_HANDLE;
static u64 g_sysres_hwm = 0;
static u64 g_remote_hwm = 0;

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

u64 nupStripCodePac(u64 addr) {
    // Horizon userland VA space is 39-bit (0..0x7f_ffff_ffff); bits 39..63 carry AArch64 PAC tags.
    return addr & ((1ULL << 39) - 1);
}

void nupFmtAddrMod(u64 addr, char* out, size_t sz) {
    addr = nupStripCodePac(addr);
    for (u32 i = 0; i < g_mods.count; i++) {
        const LoadedModule* m = &g_mods.mods[i];
        if (addr >= m->nso_base && addr < m->nso_base + m->total_size) {
            _snprintf_r(_impure_ptr, out, sz, "%s+0x%llx", m->name, (unsigned long long)(addr - m->nso_base));
            return;
        }
    }
    _snprintf_r(_impure_ptr, out, sz, "0x%llx", (unsigned long long)addr);
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

void __libnx_exception_handler(ThreadExceptionDump* ctx) {
    char pc_s[64], lr_s[64];
    nupFmtAddrMod(ctx->pc.x, pc_s, sizeof(pc_s));
    nupFmtAddrMod(ctx->lr.x, lr_s, sizeof(lr_s));
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
    nupTraceDumpRecent("LIBNX EXCEPTION", 64);
    nupLogClose();
}

static void on_sdk_user_exception(void* info) {
    if (!info) {
        nupLogf("!!! SDK USER EXCEPTION: info=NULL\n");
        nupLogFlush();
        return;
    }
    const u32* w = (const u32*)info;
    const u64* q = (const u64*)info;
    const u32 exc_type = w[0];
    const u64 fp = q[30];
    const u64 lr = nupStripCodePac(q[31]);
    const u64 sp = q[32];
    const u64 pc = nupStripCodePac(q[33]);
    const u32 esr = w[69];
    const u64 far = q[36];
    char pc_s[64], lr_s[64];
    nupFmtAddrMod(pc, pc_s, sizeof(pc_s));
    nupFmtAddrMod(lr, lr_s, sizeof(lr_s));
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
    u64 fp_addr = fp;
    for (int i = 0; i < 16 && fp_addr && (fp_addr & 7ULL) == 0; i++) {
        if (!is_readable_addr(fp_addr, 16)) break;
        const u64* fpp = (const u64*)(uintptr_t)fp_addr;
        u64 next_fp = fpp[0];
        u64 ret_lr = nupStripCodePac(fpp[1]);
        char bt_s[64];
        nupFmtAddrMod(ret_lr, bt_s, sizeof(bt_s));
        u64 soff = 0;
        const char* sym = elfAddrToSymbol(&g_mods, ret_lr >= 4 ? ret_lr - 4 : ret_lr, &soff);
        if (sym)
            nupLogf("  ex_bt[%d] %016llx (%s) %s+0x%llx\n", i, (unsigned long long)ret_lr, bt_s, sym, (unsigned long long)(soff + 4));
        else
            nupLogf("  ex_bt[%d] %016llx (%s)\n", i, (unsigned long long)ret_lr, bt_s);
        if (!next_fp || next_fp <= fp_addr || (next_fp - fp_addr) > 0x100000ULL) break;
        fp_addr = next_fp;
    }
    nupTraceDumpRecent("SDK USER EXCEPTION", 64);
    nupLogFlush();
}

static void dump_abort_info(const char* tag, const void* info) {
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    char lr_s[64];
    nupFmtAddrMod((u64)(uintptr_t)__builtin_return_address(0), lr_s, sizeof(lr_s));
    nupLogf("!!! %s(info=%p) tid=%llu lr=%s\n", tag, info, (unsigned long long)tid, lr_s);
    if (info) {
        const u64* q = (const u64*)info;
        for (int i = 0; i < 10; i++) {
            char sym_s[64];
            nupFmtAddrMod(q[i], sym_s, sizeof(sym_s));
            nupLogf("  [%d] = 0x%016llx (%s)\n", i, (unsigned long long)q[i], sym_s);
        }
        for (int i = 0; i < 10; i++) {
            if (is_readable_addr(q[i], 4)) {
                const char* s = (const char*)(uintptr_t)q[i];
                if (s[0] >= 0x20 && s[0] < 0x7f && s[1] >= 0x20 && s[1] < 0x7f) {
                    nupLogf("  str[%d] = '%.120s'\n", i, s);
                } else if (i == 0 || i == 4 || i == 5) {
                    const u32 rv = *(const u32*)(uintptr_t)q[i];
                    if (rv != 0 && R_MODULE(rv) > 0 && R_MODULE(rv) < 512) {
                        nupLogf("  res_ptr[%d] -> 0x%x (mod=%u desc=%u)\n",
                                i, rv, R_MODULE(rv), R_DESCRIPTION(rv));
                    }
                }
            }
        }
        dump_hex_bytes("info[1]", q[1], 0x40);
        if (q[2] != q[1]) {
            if (is_readable_addr(q[2], 1) && *(const u8*)(uintptr_t)q[2] == 0)
                nupLogf("  info[2] @ 0x%llx: \"\" (empty string)\n", (unsigned long long)q[2]);
            else
                dump_hex_bytes("info[2]", q[2], 0x20);
        }
    }
    u64* fp = (u64*)__builtin_frame_address(0);
    for (int i = 0; i < 24 && fp; i++) {
        if (!is_readable_addr((u64)(uintptr_t)fp, 16))
            break;
        u64 lr = nupStripCodePac(fp[1]);
        u64* nx = (u64*)(uintptr_t)fp[0];
        char bt_s[64];
        nupFmtAddrMod(lr, bt_s, sizeof(bt_s));
        u64 sym_off = 0;
        const char* sym = elfAddrToSymbol(&g_mods, lr >= 4 ? lr - 4 : lr, &sym_off);
        if (sym)
            nupLogf("  bt[%d] %016llx (%s) %s+0x%llx\n", i, (unsigned long long)lr, bt_s, sym, (unsigned long long)(sym_off + 4));
        else
            nupLogf("  bt[%d] %016llx (%s)\n", i, (unsigned long long)lr, bt_s);
        if (!nx || nx <= fp || (u64)(uintptr_t)nx - (u64)(uintptr_t)fp > 0x100000ULL)
            break;
        fp = nx;
    }
}

void nupLogBacktrace(const char* tag, u64 caller, u64 arg0, u64 arg1) {
    caller = nupStripCodePac(caller);
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    char lr_s[64];
    nupFmtAddrMod(caller, lr_s, sizeof(lr_s));
    u64 lr_off = 0;
    const char* lr_sym = elfAddrToSymbol(&g_mods, caller >= 4 ? caller - 4 : caller, &lr_off);
    nupLogf("!!! HOOKED %s tid=%llu caller=%s (%s+0x%llx) arg0=0x%llx arg1=0x%llx\n",
            tag, (unsigned long long)tid, lr_s, lr_sym ? lr_sym : "?",
            (unsigned long long)(lr_sym ? lr_off + 4 : 0), (unsigned long long)arg0, (unsigned long long)arg1);
    u64* fp = (u64*)__builtin_frame_address(0);
    for (int i = 0; i < 20 && fp; i++) {
        if (!is_readable_addr((u64)(uintptr_t)fp, 16))
            break;
        u64 lr = nupStripCodePac(fp[1]);
        u64* nx = (u64*)(uintptr_t)fp[0];
        char bt_s[64];
        nupFmtAddrMod(lr, bt_s, sizeof(bt_s));
        u64 sym_off = 0;
        const char* sym = elfAddrToSymbol(&g_mods, lr >= 4 ? lr - 4 : lr, &sym_off);
        if (sym)
            nupLogf("  bt[%d] %016llx (%s) %s+0x%llx\n", i, (unsigned long long)lr, bt_s, sym, (unsigned long long)(sym_off + 4));
        else
            nupLogf("  bt[%d] %016llx (%s)\n", i, (unsigned long long)lr, bt_s);
        if (!nx || nx <= fp || (u64)(uintptr_t)nx - (u64)(uintptr_t)fp > 0x100000ULL)
            break;
        fp = nx;
    }
    nupTraceDumpRecent(tag, 64);
    nupLogFlush();
}

static bool is_printable_str_at(u64 addr, size_t min_len, size_t* out_len) {
    if (!is_readable_addr(addr, min_len + 1))
        return false;
    const u8* p = (const u8*)(uintptr_t)addr;
    size_t n = 0;
    while (n < 160 && is_readable_addr(addr + n, 1)) {
        const u8 c = p[n];
        if (c == 0) break;
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f)) {
            n++;
            continue;
        }
        return false;
    }
    if (n < min_len || !is_readable_addr(addr + n, 1) || p[n] != 0)
        return false;
    if (out_len) *out_len = n;
    return true;
}

static bool is_in_module_rodata(u64 addr) {
    for (u32 m = 0; m < g_mods.count; m++) {
        const LoadedModule* mod = &g_mods.mods[m];
        if (mod->rodata_size &&
            addr >= mod->nso_base + mod->rodata_off &&
            addr < mod->nso_base + mod->rodata_off + mod->rodata_size)
            return true;
    }
    return false;
}

static u64 resolve_plt_stub_target(u64 stub_addr) {
    if ((stub_addr & 3ULL) != 0 || !is_readable_addr(stub_addr, 16))
        return 0;
    const u32* w = (const u32*)(uintptr_t)stub_addr;
    // Standard AArch64 PLT stub: adrp x16, #page ; ldr x17, [x16, #off] ; add x16, x16, #off ; br x17
    if ((w[0] & 0x9F00001Fu) == 0x90000010u && (w[1] & 0xFFC003FFu) == 0xF9400211u) {
        s64 immhi = (s64)(s32)((w[0] << 8)) >> 13; // bits [23:5] signed (19 bits)
        u64 immlo = (w[0] >> 29) & 3u;
        s64 pg_off = ((immhi << 2) | (s64)immlo) << 12;
        u64 page = (stub_addr & ~0xFFFULL) + (u64)pg_off;
        u64 lo = (u64)((w[1] >> 10) & 0xFFFu) * 8ULL;
        u64 got_slot = page + lo;
        if (is_readable_addr(got_slot, 8))
            return nupStripCodePac(*(const u64*)(uintptr_t)got_slot);
    }
    return 0;
}

void nupDiagDumpAbortContext(u64 caller) {
    caller = nupStripCodePac(caller);
    u64 tid = 0, tpidr = 0, tpidrro = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(tpidrro));
    const u64 tlr_1f0 = (tpidrro && is_readable_addr(tpidrro + 0x1f0, 16)) ? *(const u64*)(uintptr_t)(tpidrro + 0x1f0) : 0;
    const u64 tlr_1f8 = (tpidrro && is_readable_addr(tpidrro + 0x1f0, 16)) ? *(const u64*)(uintptr_t)(tpidrro + 0x1f8) : 0;
    nupLogf("  [abort-ctx tid=%llu] caller_pc=0x%llx tpidr_el0=0x%llx tpidrro_el0=0x%llx tlr[1f0]=0x%llx tlr[1f8]=0x%llx\n",
            (unsigned long long)tid, (unsigned long long)(caller >= 4 ? caller - 4 : caller),
            (unsigned long long)tpidr, (unsigned long long)tpidrro,
            (unsigned long long)tlr_1f0, (unsigned long long)tlr_1f8);
    if (tpidr && (tpidr & 7ULL) == 0 && is_readable_addr(tpidr, 0x180)) {
        const u64* tp = (const u64*)(uintptr_t)tpidr;
        nupLogf("  [abort-tls @ tpidr_el0=0x%llx (0x00..0x180)]:\n", (unsigned long long)tpidr);
        for (u32 i = 0; i < 48; i += 4) {
            nupLogf("    +%03x: %016llx %016llx %016llx %016llx\n",
                    i * 8,
                    (unsigned long long)tp[i], (unsigned long long)tp[i + 1],
                    (unsigned long long)tp[i + 2], (unsigned long long)tp[i + 3]);
        }
    }

    // 1. Dump 112 AArch64 instructions preceding abort() (captures full function prologue + guard check)
    //    and decode BL/PLT targets & ADRP+ADD rodata strings
    const u64 dump_bytes = 0x1C0;
    if (caller >= dump_bytes && (caller & 3ULL) == 0 && is_readable_addr(caller - dump_bytes, dump_bytes + 4)) {
        const u64 base_pc = caller - dump_bytes;
        const u32* ins = (const u32*)(uintptr_t)base_pc;
        const u32 nins = (u32)(dump_bytes / 4);
        char cs[64];
        nupFmtAddrMod(base_pc, cs, sizeof(cs));
        nupLogf("  [abort-code @ %s (%u insns)]:\n", cs, nins);
        for (u32 i = 0; i < nins; i += 4) {
            nupLogf("    +%03x: %08x %08x %08x %08x\n",
                    i * 4, ins[i], ins[i + 1], ins[i + 2], ins[i + 3]);
        }
        // Track ADRP base pages per register x0..x30 to resolve ADRP+ADD strings
        u64 adrp_page[32] = {};
        bool adrp_valid[32] = {};
        u64 internal_bls[4] = {};
        u32 internal_bl_count = 0;
        for (u32 i = 0; i < nins; i++) {
            const u32 w = ins[i];
            const u64 pc = base_pc + (u64)i * 4ULL;
            if ((w & 0x9F000000u) == 0x90000000u) {
                // ADRP Xd, #page
                const u32 rd = w & 31u;
                s64 immhi = (s64)(s32)(w << 8) >> 13;
                u64 immlo = (w >> 29) & 3u;
                adrp_page[rd] = (pc & ~0xFFFULL) + (u64)(((immhi << 2) | (s64)immlo) << 12);
                adrp_valid[rd] = true;
            } else if ((w & 0xFF800000u) == 0x91000000u) {
                // ADD Xd, Xn, #imm12 (shift=0)
                const u32 rd = w & 31u;
                const u32 rn = (w >> 5) & 31u;
                const u32 sh = (w >> 22) & 1u;
                const u64 imm = (u64)((w >> 10) & 0xFFFu) << (sh ? 12 : 0);
                if (adrp_valid[rn]) {
                    const u64 target = adrp_page[rn] + imm;
                    size_t slen = 0;
                    if (is_in_module_rodata(target) && is_printable_str_at(target, 3, &slen)) {
                        char pcs[64], ts[64];
                        nupFmtAddrMod(pc, pcs, sizeof(pcs));
                        nupFmtAddrMod(target, ts, sizeof(ts));
                        nupLogf("  [abort-str @ %s -> %s]: '%.140s'\n", pcs, ts, (const char*)(uintptr_t)target);
                    }
                }
                adrp_valid[rd] = false;
            } else if ((w & 0xFC000000u) == 0x94000000u) {
                // BL #imm26
                s64 off26 = (s64)(s32)(w << 6) >> 4;
                const u64 tgt = pc + (u64)off26;
                const u64 plt_tgt = resolve_plt_stub_target(tgt);
                char pcs[64], ts[64], ps[64];
                nupFmtAddrMod(pc, pcs, sizeof(pcs));
                nupFmtAddrMod(tgt, ts, sizeof(ts));
                u64 soff = 0;
                const char* sym = elfAddrToSymbol(&g_mods, plt_tgt ? plt_tgt : tgt, &soff);
                if (plt_tgt) {
                    nupFmtAddrMod(plt_tgt, ps, sizeof(ps));
                    nupLogf("  [abort-bl @ %s]: BL %s -> PLT %s (%s+0x%llx)\n",
                            pcs, ts, ps, sym ? sym : "?", (unsigned long long)(sym ? soff : 0));
                } else {
                    nupLogf("  [abort-bl @ %s]: BL %s (%s+0x%llx)\n",
                            pcs, ts, sym ? sym : "?", (unsigned long long)(sym ? soff : 0));
                    bool dup = false;
                    for (u32 k = 0; k < internal_bl_count; k++)
                        if (internal_bls[k] == tgt) { dup = true; break; }
                    if (!dup && internal_bl_count < 4)
                        internal_bls[internal_bl_count++] = tgt;
                }
            }
        }
        // Dump up to 48 instructions of each unique internal BL target before abort(),
        // and generically inspect any singleton object loaded via ADRP + LDR X0, [Xn, #imm]
        for (u32 b = 0; b < internal_bl_count; b++) {
            const u64 tgt = internal_bls[b];
            if (!tgt || (tgt & 3ULL) != 0 || !is_readable_addr(tgt, 0xC0))
                continue;
            const u32* cal = (const u32*)(uintptr_t)tgt;
            char ls[64];
            nupFmtAddrMod(tgt, ls, sizeof(ls));
            nupLogf("  [abort-callee #%u @ %s (48 insns)]:\n", b, ls);
            for (u32 i = 0; i < 48; i += 4) {
                nupLogf("    +%02x: %08x %08x %08x %08x\n",
                        i * 4, cal[i], cal[i + 1], cal[i + 2], cal[i + 3]);
            }
            u64 c_adrp[32] = {};
            bool c_valid[32] = {};
            bool inspected_obj = false;
            for (u32 i = 0; i < 24 && !inspected_obj; i++) {
                const u32 w = cal[i];
                const u64 pc = tgt + (u64)i * 4ULL;
                if (w == 0xD65F03C0u) break; // RET
                if ((w & 0x9F000000u) == 0x90000000u) {
                    const u32 rd = w & 31u;
                    s64 immhi = (s64)(s32)(w << 8) >> 13;
                    u64 immlo = (w >> 29) & 3u;
                    c_adrp[rd] = (pc & ~0xFFFULL) + (u64)(((immhi << 2) | (s64)immlo) << 12);
                    c_valid[rd] = true;
                } else if ((w & 0xFFC0001Fu) == 0xF9400000u) {
                    // LDR X0, [Xn, #imm12*8]
                    const u32 rn = (w >> 5) & 31u;
                    const u64 off = (u64)((w >> 10) & 0xFFFu) * 8ULL;
                    if (c_valid[rn]) {
                        const u64 slot = c_adrp[rn] + off;
                        if ((slot & 7ULL) == 0 && is_readable_addr(slot, 8)) {
                            const u64 obj = *(const u64*)(uintptr_t)slot;
                            char ss[64];
                            nupFmtAddrMod(slot, ss, sizeof(ss));
                            nupLogf("  [abort-obj #%u slot=%s -> obj=0x%llx]\n",
                                    b, ss, (unsigned long long)obj);
                            if (obj && (obj & 7ULL) == 0 && is_readable_addr(obj, 0x80)) {
                                const u64* oq = (const u64*)(uintptr_t)obj;
                                for (u32 k = 0; k < 16; k += 4) {
                                    nupLogf("    obj+%02x: %016llx %016llx %016llx %016llx\n",
                                            k * 8,
                                            (unsigned long long)oq[k], (unsigned long long)oq[k + 1],
                                            (unsigned long long)oq[k + 2], (unsigned long long)oq[k + 3]);
                                }
                                for (u32 k = 0; k < 8; k++) {
                                    size_t slen = 0;
                                    if (is_in_module_rodata(oq[k]) && is_printable_str_at(oq[k], 2, &slen)) {
                                        nupLogf("    obj+%02x str: '%.96s'\n", k * 8, (const char*)(uintptr_t)oq[k]);
                                    }
                                }
                                const u64 vt = nupStripCodePac(oq[0]);
                                if (vt && (vt & 7ULL) == 0 && is_readable_addr(vt, 0x30)) {
                                    const u64* vq = (const u64*)(uintptr_t)vt;
                                    char vts[64], f2s[64];
                                    const u64 fn2 = nupStripCodePac(vq[2]);
                                    nupFmtAddrMod(vt, vts, sizeof(vts));
                                    nupFmtAddrMod(fn2, f2s, sizeof(f2s));
                                    nupLogf("    vtable=%s [0]=0x%llx [1]=0x%llx [2]=%s [3]=0x%llx\n",
                                            vts, (unsigned long long)vq[0], (unsigned long long)vq[1],
                                            f2s, (unsigned long long)vq[3]);
                                    if (fn2 && (fn2 & 3ULL) == 0 && is_readable_addr(fn2, 0x80)) {
                                        const u32* fi = (const u32*)(uintptr_t)fn2;
                                        nupLogf("    [vtable[2] @ %s (32 insns)]:\n", f2s);
                                        for (u32 k = 0; k < 32; k += 4) {
                                            nupLogf("      +%02x: %08x %08x %08x %08x\n",
                                                    k * 4, fi[k], fi[k + 1], fi[k + 2], fi[k + 3]);
                                        }
                                        // Follow any tail-call B #imm26 inside vtable[2] (skip short thunk hops)
                                        for (u32 k = 4; k < 32; k++) {
                                            if ((fi[k] & 0xFC000000u) == 0x14000000u) {
                                                s64 boff = (s64)(s32)(fi[k] << 6) >> 4;
                                                const u64 btgt = fn2 + (u64)k * 4ULL + (u64)boff;
                                                if ((btgt & 3ULL) == 0 && is_readable_addr(btgt, 0x80)) {
                                                    const u32* bi = (const u32*)(uintptr_t)btgt;
                                                    char bts[64];
                                                    nupFmtAddrMod(btgt, bts, sizeof(bts));
                                                    nupLogf("    [vtable[2]-tail @ %s (32 insns)]:\n", bts);
                                                    for (u32 j = 0; j < 32; j += 4) {
                                                        nupLogf("      +%02x: %08x %08x %08x %08x\n",
                                                                j * 4, bi[j], bi[j + 1], bi[j + 2], bi[j + 3]);
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                                // Follow one delegation hop to any embedded backing object with a vtable
                                for (u32 k = 1; k < 8; k++) {
                                    const u64 sub = oq[k];
                                    if (!sub || sub == obj || (sub & 7ULL) != 0 || is_in_module_rodata(sub))
                                        continue;
                                    if (!is_readable_addr(sub, 0xC0))
                                        continue;
                                    const u64* sq = (const u64*)(uintptr_t)sub;
                                    const u64 svt = nupStripCodePac(sq[0]);
                                    if (!svt || (svt & 7ULL) != 0 || !is_readable_addr(svt, 0xA0))
                                        continue;
                                    const u64* svq = (const u64*)(uintptr_t)svt;
                                    const u64 sfn2 = nupStripCodePac(svq[2]);
                                    bool sfn2_is_code = false;
                                    for (u32 m = 0; m < g_mods.count; m++) {
                                        const LoadedModule* mod = &g_mods.mods[m];
                                        if (mod->rodata_off && sfn2 >= mod->nso_base && sfn2 < mod->nso_base + mod->rodata_off) {
                                            sfn2_is_code = true;
                                            break;
                                        }
                                    }
                                    if (!sfn2_is_code || (sfn2 & 3ULL) != 0 || !is_readable_addr(sfn2, 0xC0))
                                        continue;
                                    char svts[64], sf2s[64];
                                    nupFmtAddrMod(svt, svts, sizeof(svts));
                                    nupFmtAddrMod(sfn2, sf2s, sizeof(sf2s));
                                    nupLogf("  [abort-subobj obj+%02x -> sub=0x%llx vtable=%s vtable[2]=%s]\n",
                                            k * 8, (unsigned long long)sub, svts, sf2s);
                                    for (u32 j = 0; j < 24; j += 4) {
                                        nupLogf("    sub+%02x: %016llx %016llx %016llx %016llx\n",
                                                j * 8,
                                                (unsigned long long)sq[j], (unsigned long long)sq[j + 1],
                                                (unsigned long long)sq[j + 2], (unsigned long long)sq[j + 3]);
                                    }
                                    for (u32 j = 0; j < 12; j++) {
                                        size_t slen = 0;
                                        if (is_in_module_rodata(sq[j]) && is_printable_str_at(sq[j], 2, &slen)) {
                                            nupLogf("    sub+%02x str: '%.96s'\n", j * 8, (const char*)(uintptr_t)sq[j]);
                                        }
                                    }
                                    // Dump CentralResource/sub vtable[0..15]
                                    {
                                        nupLogf("    [sub vtable @ %s]:\n", svts);
                                        for (u32 vi = 0; vi < 16; vi++) {
                                            const u64 vf = nupStripCodePac(svq[vi]);
                                            if (!vf) continue;
                                            char vfs[64];
                                            nupFmtAddrMod(vf, vfs, sizeof(vfs));
                                            nupLogf("      vt[%u]=%s\n", vi, vfs);
                                        }
                                    }
                                    const u32* sfi = (const u32*)(uintptr_t)sfn2;
                                    nupLogf("    [sub->vtable[2] @ %s (48 insns)]:\n", sf2s);
                                    for (u32 j = 0; j < 48; j += 4) {
                                        nupLogf("      +%02x: %08x %08x %08x %08x\n",
                                                j * 4, sfi[j], sfi[j + 1], sfi[j + 2], sfi[j + 3]);
                                    }
                                    // Unwrap 3-insn virtual forwarding thunk: ldr x8, [x0, #imm]! ; ldr xR, [x8, #16] ; br xR
                                    if ((sfi[0] & 0xFFE00FFFu) == 0xF8400C08u && (sfi[2] & 0xFFFFFC1Fu) == 0xD61F0000u) {
                                        const s64 simm9 = (s64)(s32)(sfi[0] << 11) >> 23;
                                        const u64 emb = sub + (u64)simm9;
                                        if ((emb & 7ULL) == 0 && is_readable_addr(emb, 0x40)) {
                                            const u64 evt = nupStripCodePac(*(const u64*)(uintptr_t)emb);
                                            if (evt && (evt & 7ULL) == 0 && is_readable_addr(evt, 0x80)) {
                                                const u64* evq = (const u64*)(uintptr_t)evt;
                                                const u64 efn2 = nupStripCodePac(evq[2]);
                                                char evts[64], ef2s[64];
                                                nupFmtAddrMod(evt, evts, sizeof(evts));
                                                nupFmtAddrMod(efn2, ef2s, sizeof(ef2s));
                                                nupLogf("  [abort-emb thunk -> emb=0x%llx (sub+0x%llx) vtable=%s vtable[2]=%s]\n",
                                                        (unsigned long long)emb, (unsigned long long)simm9, evts, ef2s);
                                                for (u32 vi = 0; vi < 16; vi++) {
                                                    const u64 vf = nupStripCodePac(evq[vi]);
                                                    if (!vf) continue;
                                                    char vfs[64];
                                                    nupFmtAddrMod(vf, vfs, sizeof(vfs));
                                                    nupLogf("    emb vt[%u]=%s\n", vi, vfs);
                                                }
                                                // Skip repeating 0x20-byte small-block bin array if present, then dump trailing fields
                                                u32 bin_cnt = 0;
                                                u64 tail_off = 0;
                                                if (is_readable_addr(emb, 0x640)) {
                                                    const u64* eq = (const u64*)(uintptr_t)emb;
                                                    const u64 bin_tag = eq[1];
                                                    if (bin_tag != 0 && eq[5] == bin_tag) {
                                                        while (bin_cnt < 48 && eq[bin_cnt * 4 + 1] == bin_tag)
                                                            bin_cnt++;
                                                        tail_off = (u64)bin_cnt * 0x20ULL;
                                                        nupLogf("    emb bins=%u (tag=0x%llx, end=emb+0x%llx)\n",
                                                                bin_cnt, (unsigned long long)bin_tag, (unsigned long long)tail_off);
                                                    }
                                                    // Dump 0x140 bytes after the bin array (bounded by 0x640)
                                                    u64 dump_end = tail_off + 0x140ULL;
                                                    if (dump_end > 0x640ULL) dump_end = 0x640ULL;
                                                    for (u64 off = tail_off; off + 32 <= dump_end; off += 32) {
                                                        const u32 qi = (u32)(off / 8);
                                                        nupLogf("    emb+%03llx: %016llx %016llx %016llx %016llx\n",
                                                                (unsigned long long)off,
                                                                (unsigned long long)eq[qi], (unsigned long long)eq[qi + 1],
                                                                (unsigned long long)eq[qi + 2], (unsigned long long)eq[qi + 3]);
                                                    }
                                                    // Scan emb[0..0x640] for .rodata strings
                                                    for (u32 qi = 0; qi < 0x640 / 8; qi++) {
                                                        size_t slen = 0;
                                                        if (is_in_module_rodata(eq[qi]) && is_printable_str_at(eq[qi], 2, &slen)) {
                                                            nupLogf("    emb+%03x str: '%.96s'\n", qi * 8, (const char*)(uintptr_t)eq[qi]);
                                                        }
                                                    }
                                                }
                                                if (efn2 && (efn2 & 3ULL) == 0 && is_readable_addr(efn2, 0x180)) {
                                                    nupLogf("    [emb->vtable[2] @ %s (96 insns)]:\n", ef2s);
                                                    const u32* efi = (const u32*)(uintptr_t)efn2;
                                                    for (u32 j = 0; j < 96; j += 4) {
                                                        nupLogf("      +%03x: %08x %08x %08x %08x\n",
                                                                j * 4, efi[j], efi[j + 1], efi[j + 2], efi[j + 3]);
                                                    }
                                                    // Follow up to 4 unique internal BL or tail-call B targets in emb->vtable[2]
                                                    u64 ecallees[4] = {};
                                                    u32 ecal_cnt = 0;
                                                    for (u32 j = 0; j < 96 && ecal_cnt < 4; j++) {
                                                        const u32 ew = efi[j];
                                                        if ((ew & 0xFC000000u) == 0x94000000u || (ew & 0xFC000000u) == 0x14000000u) {
                                                            s64 boff = (s64)(s32)(ew << 6) >> 4;
                                                            const u64 btgt = efn2 + (u64)j * 4ULL + (u64)boff;
                                                            if (btgt >= efn2 && btgt < efn2 + 0x180ULL)
                                                                continue; // internal branch inside same dump
                                                            bool seen = false;
                                                            for (u32 s = 0; s < ecal_cnt; s++)
                                                                if (ecallees[s] == btgt) { seen = true; break; }
                                                            if (seen) continue;
                                                            if ((btgt & 3ULL) == 0 && is_readable_addr(btgt, 0xC0)) {
                                                                ecallees[ecal_cnt++] = btgt;
                                                                char ets[64];
                                                                nupFmtAddrMod(btgt, ets, sizeof(ets));
                                                                nupLogf("    [emb-callee #%u @ %s (48 insns)]:\n", ecal_cnt, ets);
                                                                const u32* eci = (const u32*)(uintptr_t)btgt;
                                                                for (u32 m = 0; m < 48; m += 4) {
                                                                    nupLogf("      +%02x: %08x %08x %08x %08x\n",
                                                                            m * 4, eci[m], eci[m + 1], eci[m + 2], eci[m + 3]);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // Also inspect sub's own backing pointer at sub+0x20 if it points to a vtable object
                                    const u64 leaf = sq[4];
                                    if (leaf && leaf != sub && leaf != obj && (leaf & 7ULL) == 0 &&
                                        !is_in_module_rodata(leaf) && is_readable_addr(leaf, 0x100)) {
                                        const u64* lq = (const u64*)(uintptr_t)leaf;
                                        const u64 lvt = nupStripCodePac(lq[0]);
                                        if (lvt && (lvt & 7ULL) == 0 && is_readable_addr(lvt, 0x80)) {
                                            const u64* lvq = (const u64*)(uintptr_t)lvt;
                                            const u64 lfn2 = nupStripCodePac(lvq[2]);
                                            bool lfn2_is_code = false;
                                            for (u32 m = 0; m < g_mods.count; m++) {
                                                const LoadedModule* mod = &g_mods.mods[m];
                                                if (mod->rodata_off && lfn2 >= mod->nso_base && lfn2 < mod->nso_base + mod->rodata_off) {
                                                    lfn2_is_code = true;
                                                    break;
                                                }
                                            }
                                            if (lfn2_is_code && (lfn2 & 3ULL) == 0 && is_readable_addr(lfn2, 0x100)) {
                                                char lvts[64], lf2s[64];
                                                nupFmtAddrMod(lvt, lvts, sizeof(lvts));
                                                nupFmtAddrMod(lfn2, lf2s, sizeof(lf2s));
                                                nupLogf("  [abort-leaf sub+20 -> leaf=0x%llx vtable=%s vtable[2]=%s]\n",
                                                        (unsigned long long)leaf, lvts, lf2s);
                                                for (u32 vi = 0; vi < 16; vi++) {
                                                    const u64 vf = nupStripCodePac(lvq[vi]);
                                                    if (!vf) continue;
                                                    char vfs[64];
                                                    nupFmtAddrMod(vf, vfs, sizeof(vfs));
                                                    nupLogf("    leaf vt[%u]=%s\n", vi, vfs);
                                                }
                                                for (u32 j = 0; j < 32; j += 4) {
                                                    nupLogf("    leaf+%02x: %016llx %016llx %016llx %016llx\n",
                                                            j * 8,
                                                            (unsigned long long)lq[j], (unsigned long long)lq[j + 1],
                                                            (unsigned long long)lq[j + 2], (unsigned long long)lq[j + 3]);
                                                }
                                                for (u32 j = 0; j < 32; j++) {
                                                    size_t slen = 0;
                                                    if (is_in_module_rodata(lq[j]) && is_printable_str_at(lq[j], 2, &slen)) {
                                                        nupLogf("    leaf+%02x str: '%.96s'\n", j * 8, (const char*)(uintptr_t)lq[j]);
                                                    }
                                                }
                                                const u32* lfi = (const u32*)(uintptr_t)lfn2;
                                                nupLogf("    [leaf->vtable[2] @ %s (64 insns)]:\n", lf2s);
                                                for (u32 j = 0; j < 64; j += 4) {
                                                    nupLogf("      +%02x: %08x %08x %08x %08x\n",
                                                            j * 4, lfi[j], lfi[j + 1], lfi[j + 2], lfi[j + 3]);
                                                }
                                                // Follow first external BL or B from leaf->vtable[2]
                                                for (u32 j = 0; j < 64; j++) {
                                                    const u32 lw = lfi[j];
                                                    if ((lw & 0xFC000000u) == 0x94000000u || (lw & 0xFC000000u) == 0x14000000u) {
                                                        s64 boff = (s64)(s32)(lw << 6) >> 4;
                                                        const u64 btgt = lfn2 + (u64)j * 4ULL + (u64)boff;
                                                        if (btgt >= lfn2 && btgt < lfn2 + 0x100ULL)
                                                            continue;
                                                        if ((btgt & 3ULL) == 0 && is_readable_addr(btgt, 0xC0)) {
                                                            char lts[64];
                                                            nupFmtAddrMod(btgt, lts, sizeof(lts));
                                                            nupLogf("    [leaf-callee @ %s (48 insns)]:\n", lts);
                                                            const u32* lci = (const u32*)(uintptr_t)btgt;
                                                            for (u32 m = 0; m < 48; m += 4) {
                                                                nupLogf("      +%02x: %08x %08x %08x %08x\n",
                                                                        m * 4, lci[m], lci[m + 1], lci[m + 2], lci[m + 3]);
                                                            }
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                            inspected_obj = true;
                        }
                    }
                }
            }
        }
    }

    // 1b. One-time scan for `msr tpidr_el0, xN` in loaded game/SDK modules + worker entry dump
    static volatile u32 g_tpidr_scan_once = 0;
    if (__atomic_exchange_n(&g_tpidr_scan_once, 1u, __ATOMIC_ACQ_REL) == 0u) {
        // Dump this worker's thread entry function if tracked
        u32 wcnt = __atomic_load_n(&g_worker_count, __ATOMIC_ACQUIRE);
        if (wcnt > MAX_TRACKED_WORKERS) wcnt = MAX_TRACKED_WORKERS;
        for (u32 wi = 0; wi < wcnt; wi++) {
            if (g_workers[wi].tid == tid && g_workers[wi].fn) {
                const u64 fn = nupStripCodePac((u64)(uintptr_t)g_workers[wi].fn);
                if ((fn & 3ULL) == 0 && is_readable_addr(fn, 0x100)) {
                    char fns[64];
                    nupFmtAddrMod(fn, fns, sizeof(fns));
                    nupLogf("  [abort-worker-fn '%s' @ %s (64 insns)]:\n", g_workers[wi].name, fns);
                    const u32* wi_ins = (const u32*)(uintptr_t)fn;
                    for (u32 k = 0; k < 64; k += 4) {
                        nupLogf("    +%02x: %08x %08x %08x %08x\n",
                                k * 4, wi_ins[k], wi_ins[k + 1], wi_ins[k + 2], wi_ins[k + 3]);
                    }
                }
                break;
            }
        }
        // Scan non-compat modules' .text for `msr tpidr_el0, xN` (0xD51BD040..0xD51BD05F)
        u32 hits = 0;
        for (u32 m = 0; m < g_mods.count && hits < 12; m++) {
            const LoadedModule* mod = &g_mods.mods[m];
            if (mod->is_compat || !mod->rodata_off)
                continue;
            const u32* text = (const u32*)(uintptr_t)mod->nso_base;
            const u32 nwords = (u32)(mod->rodata_off / 4ULL);
            for (u32 i = 0; i < nwords && hits < 12; i++) {
                if ((text[i] & 0xFFFFFFE0u) == 0xD51BD040u) {
                    const u64 hit_pc = mod->nso_base + (u64)i * 4ULL;
                    char hs[64];
                    nupFmtAddrMod(hit_pc, hs, sizeof(hs));
                    u64 sym_off = 0;
                    const char* sym = elfAddrToSymbol(&g_mods, hit_pc, &sym_off);
                    nupLogf("  [msr-tpidr #%u @ %s (%s+0x%llx) (reg=x%u)]:\n",
                            hits, hs, sym ? sym : "?", (unsigned long long)sym_off, text[i] & 31u);
                    const u32 back = (hits == 0) ? 128u : (hits == 1 ? 80u : 12u);
                    const u32 fwd = (hits == 1) ? 20u : 8u;
                    const u32 lo = (i >= back) ? (i - back) : 0;
                    const u32 hi = (i + fwd <= nwords) ? (i + fwd) : nwords;
                    for (u32 k = lo; k < hi; k += 4) {
                        u32 w0 = text[k];
                        u32 w1 = (k + 1 < hi) ? text[k + 1] : 0;
                        u32 w2 = (k + 2 < hi) ? text[k + 2] : 0;
                        u32 w3 = (k + 3 < hi) ? text[k + 3] : 0;
                        nupLogf("    +%08x: %08x %08x %08x %08x\n",
                                k * 4, w0, w1, w2, w3);
                    }
                    hits++;
                }
            }
        }
        nupLogf("  [msr-tpidr scan done: %u hit(s)]\n", hits);
    }

    // 2. Step up out of our own diag/hook frames to the aborting caller's stack frame
    u64 frame = (u64)(uintptr_t)__builtin_frame_address(0);
    for (int up = 0; up < 2 && frame && (frame & 7ULL) == 0 && is_readable_addr(frame, 16); up++) {
        u64 next = *(const u64*)(uintptr_t)frame;
        if (!next || next <= frame || (next - frame) > 0x40000ULL)
            break;
        frame = next;
    }
    if (!frame || (frame & 7ULL) != 0)
        return;

    // Intersect scan range with the thread's validated stack VMA bounds
    MemoryInfo smi = {};
    u32 spi = 0;
    if (R_FAILED(svcQueryMemory(&smi, &spi, frame)) || !(smi.perm & Perm_R))
        return;
    const u64 stack_low = smi.addr;
    const u64 stack_high = smi.addr + smi.size;
    // Start slightly below caller's FP (local buffers live below FP on AArch64!)
    const u64 scan_start = (frame > stack_low + 0x1000ULL) ? (frame - 0x1000ULL) : stack_low;
    const u64 scan_end = (frame + 0x3000ULL < stack_high) ? (frame + 0x3000ULL) : stack_high;
    nupLogf("  [abort-stack-range] caller_fp=0x%llx stack=[0x%llx..0x%llx) scan=[0x%llx..0x%llx)\n",
            (unsigned long long)frame, (unsigned long long)stack_low, (unsigned long long)stack_high,
            (unsigned long long)scan_start, (unsigned long long)scan_end);

    // 2a. Stack pointers into module .rodata strings
    u32 ptr_hits = 0;
    u64 seen_ptrs[16] = {};
    for (u64 addr = (scan_start & ~7ULL); addr + 8 <= scan_end && ptr_hits < 16; addr += 8) {
        const u64 val = *(const u64*)(uintptr_t)addr;
        if (!is_in_module_rodata(val))
            continue;
        bool dup = false;
        for (u32 k = 0; k < ptr_hits; k++)
            if (seen_ptrs[k] == val) { dup = true; break; }
        if (dup) continue;
        size_t slen = 0;
        if (is_printable_str_at(val, 4, &slen)) {
            seen_ptrs[ptr_hits++] = val;
            char rs[64];
            nupFmtAddrMod(val, rs, sizeof(rs));
            nupLogf("  [abort-rodata @ 0x%llx -> %s]: '%.120s'\n",
                    (unsigned long long)addr, rs, (const char*)(uintptr_t)val);
        }
    }
    // 2b. Inline ASCII strings on caller's stack
    u32 str_hits = 0;
    for (u64 addr = scan_start; addr + 16 <= scan_end && str_hits < 16; ) {
        const u8* p = (const u8*)(uintptr_t)addr;
        if (p[0] >= 0x20 && p[0] < 0x7f) {
            size_t n = 0;
            while (addr + n < scan_end && n < 160) {
                const u8 c = p[n];
                if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f))
                    n++;
                else
                    break;
            }
            if (n >= 8 && addr + n < scan_end && p[n] == 0) {
                char clean[164];
                size_t cp = n < 160 ? n : 160;
                for (size_t j = 0; j < cp; j++)
                    clean[j] = (p[j] == '\n' || p[j] == '\r' || p[j] == '\t') ? ' ' : (char)p[j];
                clean[cp] = '\0';
                nupLogf("  [abort-stack @ 0x%llx]: '%s'\n", (unsigned long long)addr, clean);
                str_hits++;
                addr += n + 1;
                continue;
            }
        }
        addr++;
    }
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

void nupDiagReset(void) {
    g_abort_observers_registered = false;
    g_sdk_ex_registered = false;
    g_worker_count = 0;
    g_sysres_hwm = 0;
    g_remote_hwm = 0;
}

void nupDiagRegisterExceptionHandler(bool force) {
    if (g_sdk_ex_registered && !force)
        return;
    typedef void (*SetUserExFn)(void (*)(void*), void*, size_t, void*);
    const u64 fn = elfFindSymbol(&g_mods, "_ZN2nn2os23SetUserExceptionHandlerEPFvPNS0_17UserExceptionInfoEEPvmS2_");
    if (fn) {
        ((SetUserExFn)(uintptr_t)fn)(on_sdk_user_exception, g_sdk_ex_stack, sizeof(g_sdk_ex_stack), g_sdk_ex_info);
        if (!g_sdk_ex_registered)
            nupLogf("[6/6] registered nn::os::SetUserExceptionHandler\n");
        g_sdk_ex_registered = true;
    } else if (!g_sdk_ex_registered) {
        nupLogf("[6/6] SetUserExceptionHandler not found; scanning...\n");
        elfLogMatchingSymbols(&g_mods, "SetUserExceptionHandler");
    }
}

void nupDiagRegisterAbortObservers(void) {
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
    nupDiagRegisterExceptionHandler(false);
    nupDiagRegisterAbortObservers();
}

void nupOnBeforeNninitStartup(void) {
    nupDiagRegisterExceptionHandler(false);
}

void nupOnBeforeNnMain(void) {
    // Re-register in case compat2/nninitStartup/static constructors replaced the user handler.
    nupDiagRegisterExceptionHandler(true);
    nupDiagRegisterAbortObservers();
    u64 tpidr = 0, tpidrro = 0;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(tpidrro));
    const u64 tlr_1f0 = (tpidrro && is_readable_addr(tpidrro + 0x1f0, 16)) ? *(const u64*)(uintptr_t)(tpidrro + 0x1f0) : 0;
    const u64 tlr_1f8 = (tpidrro && is_readable_addr(tpidrro + 0x1f0, 16)) ? *(const u64*)(uintptr_t)(tpidrro + 0x1f8) : 0;
    nupLogf("[6/6] before nnMain: main tpidr_el0=0x%llx tpidrro_el0=0x%llx tlr[1f0]=0x%llx tlr[1f8]=0x%llx\n",
            (unsigned long long)tpidr, (unsigned long long)tpidrro,
            (unsigned long long)tlr_1f0, (unsigned long long)tlr_1f8);
    if (tpidr && (tpidr & 7ULL) == 0 && is_readable_addr(tpidr, 0xC0)) {
        const u64* tp = (const u64*)(uintptr_t)tpidr;
        for (u32 i = 0; i < 24; i += 4) {
            nupLogf("  [main-tls +%02x]: %016llx %016llx %016llx %016llx\n",
                    i * 8,
                    (unsigned long long)tp[i], (unsigned long long)tp[i + 1],
                    (unsigned long long)tp[i + 2], (unsigned long long)tp[i + 3]);
        }
    }
}

void nupRecordWorkerThread(void* thread_type, void* fn) {
    if (!thread_type || g_worker_count >= MAX_TRACKED_WORKERS)
        return;
    const u32* words = (const u32*)thread_type;
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

static void update_sysres_hwm(u64 cur) {
    if (cur > g_sysres_hwm)
        g_sysres_hwm = cur;
}

static void log_heartbeat_stats(u32 sec) {
    u64 used = 0, sys_used = 0, sys_tot = 0, ns_used = 0, ns_tot = 0;
    u64 rem_used = 0, rem_tot = 0;
    Result urc = svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&ns_used, InfoType_UsedNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&ns_tot, InfoType_TotalNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
    const bool has_rem = R_SUCCEEDED(svcGetInfo(&rem_tot, 31, CUR_PROCESS_HANDLE, 0));
    if (has_rem) {
        svcGetInfo(&rem_used, 32, CUR_PROCESS_HANDLE, 0);
        if (rem_used > g_remote_hwm)
            g_remote_hwm = rem_used;
    }
    update_sysres_hwm(sys_used);
    if (nupTraceIsEnabled()) {
        nupLogf("[hb] %us used=0x%llx(rc=0x%x) ns=0x%llx/0x%llx sysres=0x%llx/0x%llx(hwm=0x%llx) gpu=0x%llx/0x%llx(hwm=0x%llx) files=%u workers=%u reent=%u tr_seq=%llu drop=%llu\n",
                sec, (unsigned long long)used, urc,
                (unsigned long long)ns_used, (unsigned long long)ns_tot,
                (unsigned long long)sys_used, (unsigned long long)sys_tot,
                (unsigned long long)g_sysres_hwm,
                (unsigned long long)rem_used, (unsigned long long)rem_tot,
                (unsigned long long)g_remote_hwm,
                g_open_file_count, g_worker_count, g_bad_reent_count,
                (unsigned long long)nupTraceTotalSeq(),
                (unsigned long long)nupTraceDroppedCount());
    } else {
        nupLogf("[hb] %us used=0x%llx(rc=0x%x) ns=0x%llx/0x%llx sysres=0x%llx/0x%llx(hwm=0x%llx) gpu=0x%llx/0x%llx(hwm=0x%llx) files=%u workers=%u reent=%u\n",
                sec, (unsigned long long)used, urc,
                (unsigned long long)ns_used, (unsigned long long)ns_tot,
                (unsigned long long)sys_used, (unsigned long long)sys_tot,
                (unsigned long long)g_sysres_hwm,
                (unsigned long long)rem_used, (unsigned long long)rem_tot,
                (unsigned long long)g_remote_hwm,
                g_open_file_count, g_worker_count, g_bad_reent_count);
    }
}

static void heartbeat_thread_fn(void* arg) {
    (void)arg;
    if (nupTraceIsEnabled()) {
        // High-frequency boot drain: 25ms steps for first 1s, then 100ms steps up to 2s,
        // so even an uncatchable hardware fault shortly after nnMain leaves a full trail on SD.
        u32 elapsed_ms = 0;
        for (u32 step = 1; step <= 40; step++) {
            svcSleepThread(25000000ULL);
            elapsed_ms += 25u;
            nupTracePollHeartbeat(elapsed_ms, true);
            nupLogFlush();
            if (elapsed_ms == 1000u)
                log_heartbeat_stats(1u);
        }
        for (u32 step = 1; step <= 10; step++) {
            svcSleepThread(100000000ULL);
            elapsed_ms += 100u;
            nupTracePollHeartbeat(elapsed_ms, true);
            nupLogFlush();
            if (elapsed_ms == 2000u)
                log_heartbeat_stats(2u);
        }
    }
    const u32 start_sec = nupTraceIsEnabled() ? 3u : 1u;
    for (u32 t = start_sec; t <= 12; t++) {
        svcSleepThread(1000000000ULL);
        nupTracePollHeartbeat(t * 1000u, false);
        nupLogFlush();
        log_heartbeat_stats(t);
    }
    u32 sec = 12;
    for (;;) {
        svcSleepThread(2000000000ULL);
        sec += 2;
        nupTracePollHeartbeat(sec * 1000u, false);
        nupLogFlush();
    }
}

void nupDiagStartHeartbeat(void) {
    g_main_thread_handle = envGetMainThreadHandle();
    Result hb_rc = threadCreate(&g_hb_thread, heartbeat_thread_fn, NULL,
                                g_hb_stack, sizeof(g_hb_stack), 0x20, -2);
    if (R_SUCCEEDED(hb_rc))
        hb_rc = threadStart(&g_hb_thread);
    nupLogf("[5/6] heartbeat thread start -> 0x%x\n", hb_rc);
}

// --- Compact bounds-checked MsgPack crash summary extractor for erpt:r ---

static u64 read_be64(const u8* p) {
    return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) | ((u64)p[3] << 32) |
           ((u64)p[4] << 24) | ((u64)p[5] << 16) | ((u64)p[6] << 8)  | (u64)p[7];
}

static u32 read_be32(const u8* p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static u16 read_be16(const u8* p) {
    return (u16)(((u16)p[0] << 8) | (u16)p[1]);
}

static bool mp_read_uint(const u8* buf, size_t len, size_t* pos, u64* out) {
    if (*pos >= len) return false;
    const u8 b = buf[*pos];
    if (b <= 0x7f) { *out = b; (*pos) += 1; return true; }
    if (b >= 0xe0) { *out = (u64)(s64)(s8)b; (*pos) += 1; return true; }
    if (b == 0xcc && *pos + 2 <= len) { *out = buf[*pos + 1]; (*pos) += 2; return true; }
    if (b == 0xcd && *pos + 3 <= len) { *out = read_be16(buf + *pos + 1); (*pos) += 3; return true; }
    if (b == 0xce && *pos + 5 <= len) { *out = read_be32(buf + *pos + 1); (*pos) += 5; return true; }
    if (b == 0xcf && *pos + 9 <= len) { *out = read_be64(buf + *pos + 1); (*pos) += 9; return true; }
    if (b == 0xd0 && *pos + 2 <= len) { *out = (u64)(s64)(s8)buf[*pos + 1]; (*pos) += 2; return true; }
    if (b == 0xd1 && *pos + 3 <= len) { *out = (u64)(s64)(s16)read_be16(buf + *pos + 1); (*pos) += 3; return true; }
    if (b == 0xd2 && *pos + 5 <= len) { *out = (u64)(s64)(s32)read_be32(buf + *pos + 1); (*pos) += 5; return true; }
    if (b == 0xd3 && *pos + 9 <= len) { *out = read_be64(buf + *pos + 1); (*pos) += 9; return true; }
    return false;
}

static bool mp_read_str(const u8* buf, size_t len, size_t* pos, char* out, size_t out_sz) {
    if (*pos >= len) return false;
    const u8 b = buf[*pos];
    size_t slen = 0, hdr = 0;
    if ((b & 0xe0) == 0xa0) { slen = b & 0x1f; hdr = 1; }
    else if (b == 0xd9 && *pos + 2 <= len) { slen = buf[*pos + 1]; hdr = 2; }
    else if (b == 0xda && *pos + 3 <= len) { slen = read_be16(buf + *pos + 1); hdr = 3; }
    else return false;
    if (*pos + hdr + slen > len) return false;
    size_t cp = slen < (out_sz - 1) ? slen : (out_sz - 1);
    memcpy(out, buf + *pos + hdr, cp);
    out[cp] = '\0';
    *pos += hdr + slen;
    return true;
}

static bool erpt_key_interesting(const char* k) {
    static const char* const keys[] = {
        "ErrorCode", "ProgramId", "ApplicationId", "ProcessName", "AbortReason",
        "ExceptionType", "ExceptionDesc", "ResultCode", "ModuleName",
        "CrashThreadName", "ThreadName",
        "ProgramCounter", "LinkRegister", "StackPointer", "FramePointer",
        "FaultAddress", "FaultingAddress", "PC", "LR", "SP", "FP", "FAR", "ESR",
        "Backtrace", "StackTrace", "StackTraceSize", "NxdmpIsAttached", "SyslogIsAttached",
        NULL
    };
    for (int i = 0; keys[i]; i++) {
        if (strcmp(k, keys[i]) == 0)
            return true;
    }
    return false;
}

static void log_erpt_summary(const u8* buf, size_t len) {
    u32 logged = 0;
    for (size_t i = 0; i < len && logged < 24; ) {
        size_t p = i;
        char key[48];
        if (!mp_read_str(buf, len, &p, key, sizeof(key))) {
            i++;
            continue;
        }
        if (!erpt_key_interesting(key) || p >= len) {
            i++;
            continue;
        }
        size_t vp = p;
        char sval[96];
        u64 uval = 0;
        if (mp_read_str(buf, len, &vp, sval, sizeof(sval))) {
            nupLogf("[erpt]   %s = '%s'\n", key, sval);
            logged++;
            i = vp;
            continue;
        }
        vp = p;
        if (mp_read_uint(buf, len, &vp, &uval)) {
            nupLogf("[erpt]   %s = 0x%llx\n", key, (unsigned long long)uval);
            logged++;
            i = vp;
            continue;
        }
        if (p < len && (buf[p] == 0xc2 || buf[p] == 0xc3)) {
            nupLogf("[erpt]   %s = %s\n", key, buf[p] == 0xc3 ? "true" : "false");
            logged++;
            i = p + 1;
            continue;
        }
        // Handle MsgPack array of u64/u32 (e.g. Backtrace / StackTrace)
        const u8 b = buf[p];
        u32 arr_len = 0;
        size_t ap = p;
        if ((b & 0xf0) == 0x90) { arr_len = b & 0x0f; ap = p + 1; }
        else if (b == 0xdc && p + 3 <= len) { arr_len = read_be16(buf + p + 1); ap = p + 3; }
        if (arr_len > 0 && arr_len <= 32) {
            char line[256];
            int lpos = snprintf(line, sizeof(line), "[erpt]   %s[%u] =", key, arr_len);
            bool ok = true;
            for (u32 k = 0; k < arr_len && k < 8; k++) {
                u64 elem = 0;
                if (!mp_read_uint(buf, len, &ap, &elem)) { ok = false; break; }
                if (lpos > 0 && (size_t)lpos < sizeof(line) - 24)
                    lpos += snprintf(line + lpos, sizeof(line) - (size_t)lpos, " 0x%llx", (unsigned long long)elem);
            }
            if (ok) {
                nupLogf("%s\n", line);
                logged++;
                i = ap;
                continue;
            }
        }
        i = p;
    }
}

// Pull erpt attachments (nxdmp holds the registers/backtrace the context report lacks).
static void nupDiagDumpAttachments(Service* r, Service* mgr, const u8* rep_id, FsFileSystem* sd) {
    static u8 alist[0x200];
    static u8 abuf[0x10000];
    memset(alist, 0, sizeof(alist));
    struct { u8 id[20]; } in;
    memcpy(in.id, rep_id, 20);
    u32 acount = 0;
    Result rc = serviceDispatchInOut(mgr, 6, in, acount,
        .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
        .buffers = {{alist, sizeof(alist)}});
    if (R_FAILED(rc) || acount == 0) {
        nupLogf("[erpt] attachments: none (rc=0x%x)\n", rc);
        return;
    }
    if (acount > 5) acount = 5;
    for (u32 i = 0; i < acount; i++) {
        const u8* e = alist + 8 + i * 0x58;
        char aname[0x21] = {};
        memcpy(aname, e + 0x38, 0x20);
        u64 asize = 0;
        memcpy(&asize, e + 0x30, 8);
        nupLogf("[erpt] attachment[%u] '%s' size=%llu\n", i, aname, (unsigned long long)asize);
        if (asize == 0) continue;
        Service att = {};
        rc = serviceDispatch(r, 2, .out_num_objects = 1, .out_objects = &att);
        if (R_FAILED(rc)) break;
        struct { u8 id[20]; } ain;
        memcpy(ain.id, e + 0x14, 20);
        rc = serviceDispatchIn(&att, 0, ain);
        s64 total = 0;
        if (R_SUCCEEDED(rc)) {
            s64 rsize = 0;
            rc = serviceDispatchOut(&att, 5, rsize);
            if (R_SUCCEEDED(rc) && rsize > 0) {
                char path[64];
                snprintf(path, sizeof(path), "/kaihen/last_attach_%u.bin", i);
                fsFsDeleteFile(sd, path);
                fsFsCreateFile(sd, path, 0, 0);
                FsFile ef = {};
                const bool f_ok = R_SUCCEEDED(fsFsOpenFile(sd, path,
                    FsOpenMode_Write | FsOpenMode_Append, &ef));
                if (asize > 0x100000) asize = 0x100000;
                while (total < (s64)asize) {
                    u32 got = 0;
                    u64 want = asize - (u64)total;
                    if (want > sizeof(abuf)) want = sizeof(abuf);
                    if (R_FAILED(serviceDispatchOut(&att, 1, got,
                            .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                            .buffers = {{abuf, (size_t)want}})) || got == 0)
                        break;
                    if (f_ok) fsFileWrite(&ef, total, abuf, got, FsWriteOption_Flush);
                    total += got;
                }
                if (f_ok) {
                    fsFileFlush(&ef);
                    fsFileClose(&ef);
                    fsFsCommit(sd);
                }
                nupLogf("[erpt] dumped %lld bytes to %s\n", (long long)total, path);
            }
            serviceDispatch(&att, 4);
        }
        serviceClose(&att);
    }
}

void nupDiagDumpLatestErpt(Handle hen_sm, FsFileSystem* sd) {
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
    if (count > 0 && sd) {
        u8 rep_id[20] = {};
        memcpy(rep_id, list + 8 + chosen_k * 0x70 + 4, 20);
        Service rep = {};
        if (R_SUCCEEDED(serviceDispatch(&r, 0, .out_num_objects = 1, .out_objects = &rep))) {
            struct { u8 id[20]; } in;
            memcpy(in.id, rep_id, 20);
            if (R_SUCCEEDED(serviceDispatchIn(&rep, 0, in))) {
                static u8 buf[0x10000];
                fsFsDeleteFile(sd, "/kaihen/last_erpt.bin");
                fsFsCreateFile(sd, "/kaihen/last_erpt.bin", 0, 0);
                FsFile ef = {};
                const bool f_ok = R_SUCCEEDED(fsFsOpenFile(sd, "/kaihen/last_erpt.bin",
                                                           FsOpenMode_Write | FsOpenMode_Append, &ef));
                s64 pos = 0;
                bool code_logged = false;
                for (u32 chunk = 0; chunk < 16 && (size_t)pos < sizeof(buf); chunk++) {
                    u32 got = 0;
                    const size_t avail = sizeof(buf) - (size_t)pos;
                    if (R_FAILED(serviceDispatchOut(&rep, 1, got,
                            .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                            .buffers = {{buf + pos, avail}})) || got == 0)
                        break;
                    if (f_ok)
                        fsFileWrite(&ef, pos, buf + pos, got, FsWriteOption_Flush);
                    pos += got;
                    if (!code_logged) {
                        for (u32 at = 0; at + 24 < (u32)pos; at++) {
                            if (memcmp(buf + at, "ErrorCode", 9) == 0 && (buf[at + 9] & 0xE0) == 0xA0) {
                                u32 len = buf[at + 9] & 31;
                                char code[32] = {};
                                memcpy(code, buf + at + 10, len < 31 ? len : 31);
                                const char* desc =
                                    strcmp(code, "2168-0000") == 0 ? " (Illegal Instruction)" :
                                    strcmp(code, "2168-0001") == 0 ? " (Instruction Abort)" :
                                    strcmp(code, "2168-0002") == 0 ? " (Data Abort)" :
                                    strcmp(code, "2168-0003") == 0 ? " (Misaligned Access)" :
                                    strcmp(code, "2168-0006") == 0 ? " (Break / Abort)" :
                                    strcmp(code, "2168-0008") == 0 ? " (Disallowed SVC)" : "";
                                nupLogf("[erpt] latest ErrorCode='%s'%s [idx=%u] (dumped %lld bytes to /kaihen/last_erpt.bin)\n",
                                        code, desc, chosen_k, (long long)pos);
                                code_logged = true;
                                break;
                            }
                        }
                    }
                }
                if (f_ok) {
                    fsFileFlush(&ef);
                    fsFileClose(&ef);
                    fsFsCommit(sd);
                }
                if (!code_logged)
                    nupLogf("[erpt] dumped %lld bytes [idx=%u] to /kaihen/last_erpt.bin\n", (long long)pos, chosen_k);
                if (pos > 0)
                    log_erpt_summary(buf, (size_t)pos);
                serviceDispatch(&rep, 4);
            }
            serviceClose(&rep);
        }
        nupDiagDumpAttachments(&r, &mgr, rep_id, sd);
    }
    serviceClose(&mgr);
    serviceClose(&r);
}
