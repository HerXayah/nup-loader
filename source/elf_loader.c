// SPDX-License-Identifier: MIT
#include "elf_loader.h"
#include "hooks.h"
#include "log.h"
#include "zbic.h"

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    s64 d_tag;
    u64 d_val;
} Elf64_Dyn;

typedef struct {
    u32 st_name;
    u8 st_info;
    u8 st_other;
    u16 st_shndx;
    u64 st_value;
    u64 st_size;
} Elf64_Sym;

typedef struct {
    u64 r_offset;
    u64 r_info;
    s64 r_addend;
} Elf64_Rela;

#define DT_NULL         0
#define DT_PLTRELSZ     2
#define DT_PLTGOT       3
#define DT_HASH         4
#define DT_STRTAB       5
#define DT_SYMTAB       6
#define DT_RELA         7
#define DT_RELASZ       8
#define DT_STRSZ        10
#define DT_INIT         12
#define DT_FINI         13
#define DT_JMPREL       23
#define DT_INIT_ARRAY   25
#define DT_INIT_ARRAYSZ 27
#define DT_RELRSZ       35
#define DT_RELR         36
#define DT_GNU_HASH     0x6ffffef5
#define DT_RELACOUNT    0x6ffffff9

#define R_AARCH64_ABS64     257
#define R_AARCH64_GLOB_DAT  1025
#define R_AARCH64_JUMP_SLOT 1026
#define R_AARCH64_RELATIVE  1027
#define R_AARCH64_TLSDESC   1031

// Per-thread AArch64 TLSDESC resolver: slot[1] holds base of a 64-slot (64 * 64B = 4KB)
// region; selects a private 64-byte slot per thread by mixing bits of tpidr_el0
// (handles 512B, 4KB, or larger thread-block alignments), preserving all regs except x0.
extern void tlsdesc_resolver(void);
__asm__(
    ".text\n"
    ".align 2\n"
    "tlsdesc_resolver:\n"
    "  stp x1, x2, [sp, #-16]!\n"
    "  ldr x0, [x0, #8]\n"
    "  mrs x1, tpidr_el0\n"
    "  eor x2, x1, x1, lsr #12\n"
    "  ubfx x2, x2, #9, #6\n"
    "  add x0, x0, x2, lsl #6\n"
    "  sub x0, x0, x1\n"
    "  ldp x1, x2, [sp], #16\n"
    "  ret\n"
);

static u8 g_tls_fallback[0x20000] __attribute__((aligned(64)));
static u32 g_tls_cursor = 0;

#define ELF64_R_SYM(i)   ((u32)((i) >> 32))
#define ELF64_R_TYPE(i)  ((u32)((i) & 0xffffffffu))
#define ELF64_ST_BIND(i) ((i) >> 4)
#define STB_WEAK 2

static u64 page_align(u64 v) {
    return (v + 0xfff) & ~(u64)0xfff;
}

static bool lz4_decompress_block(const u8* src, size_t src_len, u8* dst, size_t dst_len) {
    size_t i = 0, o = 0;
    while (i < src_len) {
        const u8 token = src[i++];
        size_t lit = token >> 4;
        if (lit == 15) {
            u8 b;
            do {
                if (i >= src_len) return false;
                b = src[i++];
                lit += b;
            } while (b == 255);
        }
        if (i + lit > src_len || o + lit > dst_len)
            return false;
        if (lit) {
            memcpy(dst + o, src + i, lit);
            i += lit;
            o += lit;
        }
        if (i >= src_len)
            break;
        if (i + 2 > src_len)
            return false;
        const size_t offset = (size_t)src[i] | ((size_t)src[i + 1] << 8);
        i += 2;
        if (offset == 0 || offset > o)
            return false;
        size_t match = (token & 0x0f) + 4;
        if ((token & 0x0f) == 15) {
            u8 b;
            do {
                if (i >= src_len) return false;
                b = src[i++];
                match += b;
            } while (b == 255);
        }
        if (o + match > dst_len)
            return false;
        size_t s = o - offset;
        for (size_t k = 0; k < match; k++)
            dst[o++] = dst[s++];
    }
    return o == dst_len;
}

static unsigned nso_rank(const char* name) {
    if (strcmp(name, "main") == 0) return 0;
    if (strncmp(name, "subsdk", 6) == 0 && name[6] >= '0' && name[6] <= '9') return 1;
    if (strcmp(name, "sdk") == 0) return 2;
    return 99;
}

static bool nso_before(const NupFileInfo* a, const NupFileInfo* b) {
    const unsigned ra = nso_rank(a->name);
    const unsigned rb = nso_rank(b->name);
    if (ra != rb) return ra < rb;
    if (ra == 1)
        return atoi(a->name + 6) < atoi(b->name + 6);
    return strcmp(a->name, b->name) < 0;
}

static bool parse_mod0(LoadedModule* mod) {
    const u8* base = (const u8*)(uintptr_t)mod->nso_base;
    u32 mod_off = 0;
    memcpy(&mod_off, base + 4, 4);
    if (mod_off == 0 || mod_off + 0x1c > mod->total_size)
        return false;
    if (memcmp(base + mod_off, "MOD0", 4) != 0)
        return false;
    s32 dyn_rel = 0, mod_obj_rel = 0;
    memcpy(&dyn_rel, base + mod_off + 4, 4);
    memcpy(&mod_obj_rel, base + mod_off + 0x18, 4);
    mod->mod0_off = mod_off;
    mod->dynamic_off = (u64)((s64)mod_off + (s64)dyn_rel);
    mod->module_object_off = mod_obj_rel ? (u64)((s64)mod_off + (s64)mod_obj_rel) : 0;
    const Elf64_Dyn* dyn = (const Elf64_Dyn*)(base + mod->dynamic_off);

    const u32* hash = NULL;
    u64 symtab_off = 0, strtab_off = 0;
    for (u32 i = 0; i < 128; i++) {
        if (dyn[i].d_tag == DT_NULL)
            break;
        switch (dyn[i].d_tag) {
        case DT_STRTAB:       strtab_off = dyn[i].d_val; break;
        case DT_SYMTAB:       symtab_off = dyn[i].d_val; break;
        case DT_STRSZ:        mod->strsz = dyn[i].d_val; break;
        case DT_HASH:         hash = (const u32*)(base + dyn[i].d_val); mod->sysv_hash_off = dyn[i].d_val; break;
        case DT_GNU_HASH:     mod->gnu_hash_off = dyn[i].d_val; break;
        case DT_PLTGOT:       mod->pltgot_off = dyn[i].d_val; break;
        case DT_RELACOUNT:    mod->relacount = dyn[i].d_val; break;
        case DT_RELA:         mod->rela = base + dyn[i].d_val; break;
        case DT_RELASZ:       mod->relasz = dyn[i].d_val; break;
        case DT_RELR:         mod->relr = (const u64*)(base + dyn[i].d_val); break;
        case DT_RELRSZ:       mod->relrsz = dyn[i].d_val; break;
        case DT_JMPREL:       mod->jmprel = base + dyn[i].d_val; break;
        case DT_PLTRELSZ:     mod->pltrelsz = dyn[i].d_val; break;
        case DT_INIT:         mod->init_fn = mod->nso_base + dyn[i].d_val; break;
        case DT_FINI:         mod->fini_fn = mod->nso_base + dyn[i].d_val; break;
        case DT_INIT_ARRAY:   mod->init_array = (const u64*)(base + dyn[i].d_val); break;
        case DT_INIT_ARRAYSZ: mod->init_arraysz = dyn[i].d_val; break;
        default: break;
        }
    }
    if (!strtab_off || !symtab_off)
        return false;
    mod->strtab = (const char*)(base + strtab_off);
    mod->symtab = base + symtab_off;
    if (hash) {
        mod->sym_count = hash[1];
    } else if (strtab_off > symtab_off) {
        mod->sym_count = (u32)((strtab_off - symtab_off) / sizeof(Elf64_Sym));
    }
    return true;
}

static Result load_one_nso(NupArchive* nup, const NupFileInfo* fi, u32 index, LoadedModule* out) {
    memset(out, 0, sizeof(*out));
    snprintf(out->name, sizeof(out->name), "%.31s", fi->name);

    u8 hdr[0x100];
    Result rc = nupReadExefs(nup, fi, 0, hdr, sizeof(hdr));
    if (R_FAILED(rc))
        return rc;
    if (memcmp(hdr, "NSO0", 4) != 0)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    u32 flags = 0;
    u32 tf, tm, ts, rf, rm, rs, df, dm, ds, bss;
    u32 tc, rc_sz, dc;
    memcpy(&flags, hdr + 0x0c, 4);
    memcpy(&tf, hdr + 0x10, 4); memcpy(&tm, hdr + 0x14, 4); memcpy(&ts, hdr + 0x18, 4);
    memcpy(&rf, hdr + 0x20, 4); memcpy(&rm, hdr + 0x24, 4); memcpy(&rs, hdr + 0x28, 4);
    memcpy(&df, hdr + 0x30, 4); memcpy(&dm, hdr + 0x34, 4); memcpy(&ds, hdr + 0x38, 4);
    memcpy(&bss, hdr + 0x3c, 4);
    memcpy(&tc, hdr + 0x60, 4); memcpy(&rc_sz, hdr + 0x64, 4); memcpy(&dc, hdr + 0x68, 4);

    if (tm != 0 || rm == 0 || dm <= rm || (rm & 0xfff) || (dm & 0xfff))
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    const u64 text_seg_sz = rm;
    const u64 ro_seg_sz = dm - rm;
    const u64 data_seg_sz = page_align(ds);
    const u64 bss_seg_sz = page_align(bss);
    const u64 nro_img_sz = 0x1000 + text_seg_sz + ro_seg_sz + data_seg_sz;

    u8* buf = (u8*)memalign(0x1000, (size_t)nro_img_sz);
    if (!buf)
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    memset(buf, 0, (size_t)nro_img_sz);

    memcpy(buf + 0x10, "NRO0", 4);
    const u32 nro_size_u32 = (u32)nro_img_sz;
    const u32 nro_flags_u32 = 1;
    const u32 nro_text_off = 0;
    const u32 nro_text_sz = (u32)(0x1000 + text_seg_sz);
    const u32 nro_ro_off = nro_text_sz;
    const u32 nro_ro_sz = (u32)ro_seg_sz;
    const u32 nro_data_off = nro_ro_off + nro_ro_sz;
    const u32 nro_data_sz = (u32)data_seg_sz;
    const u32 nro_bss_sz = (u32)bss_seg_sz;
    memcpy(buf + 0x18, &nro_size_u32, 4);
    memcpy(buf + 0x1c, &nro_flags_u32, 4);
    memcpy(buf + 0x20, &nro_text_off, 4);
    memcpy(buf + 0x24, &nro_text_sz, 4);
    memcpy(buf + 0x28, &nro_ro_off, 4);
    memcpy(buf + 0x2c, &nro_ro_sz, 4);
    memcpy(buf + 0x30, &nro_data_off, 4);
    memcpy(buf + 0x34, &nro_data_sz, 4);
    memcpy(buf + 0x38, &nro_bss_sz, 4);
    memcpy(buf + 0x40, hdr + 0x40, 32);
    buf[0x5f] ^= (u8)(index + 0xa5);

    const bool is_zbic = (flags & 0x80u) != 0;
    const u32 foffs[3] = {tf, rf, df};
    const u32 moffs[3] = {tm, rm, dm};
    const u32 dsizes[3] = {ts, rs, ds};
    const u32 csizes[3] = {tc, rc_sz, dc};

    for (int s = 0; s < 3; s++) {
        if (dsizes[s] == 0)
            continue;
        u8* dst = buf + 0x1000 + moffs[s];
        if (flags & (1u << s)) {
            u8* tmp = (u8*)malloc(csizes[s]);
            if (!tmp) {
                free(buf);
                return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            }
            rc = nupReadExefs(nup, fi, foffs[s], tmp, csizes[s]);
            if (R_SUCCEEDED(rc)) {
                const bool dec_ok = is_zbic
                    ? zbicDecompress(dst, dsizes[s], tmp, csizes[s])
                    : lz4_decompress_block(tmp, csizes[s], dst, dsizes[s]);
                if (!dec_ok) {
                    printf("  [!] %s seg[%d] %s decompress failed\n",
                           fi->name, s, is_zbic ? "ZBIC" : "LZ4");
                    consoleUpdate(NULL);
                    rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
                }
            }
            free(tmp);
            if (R_FAILED(rc)) {
                free(buf);
                return rc;
            }
        } else {
            rc = nupReadExefs(nup, fi, foffs[s], dst, dsizes[s]);
            if (R_FAILED(rc)) {
                free(buf);
                return rc;
            }
        }
    }

    // Forward the module's header pointers into page 0 of the NRO wrapper so
    // Switch 2 SDK code-segment scans (starting at nro_base) find MOD0 + header2.
    {
        u32* w = (u32*)buf;
        const u32* first = (const u32*)(buf + 0x1000);
        w[0] = first[0];
        w[1] = first[1] ? (0x1000u + first[1]) : 0;
        w[2] = first[2] ? (0x1000u + first[2]) : 0;
    }

    u8* bss_buf = NULL;
    if (bss_seg_sz) {
        bss_buf = (u8*)memalign(0x1000, (size_t)bss_seg_sz);
        if (!bss_buf) {
            free(buf);
            return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
        }
        memset(bss_buf, 0, (size_t)bss_seg_sz);
    }

    u64 nro_base = 0;
    rc = ldrRoLoadNro(&nro_base, (u64)(uintptr_t)buf, nro_img_sz,
                      (u64)(uintptr_t)bss_buf, bss_seg_sz);
    if (R_FAILED(rc)) {
        free(buf);
        free(bss_buf);
        return rc;
    }

    out->nro_base = nro_base;
    out->nso_base = nro_base + 0x1000;
    out->src_buf = buf;
    out->bss_buf = bss_buf;
    out->rodata_off = rm;
    out->rodata_size = ro_seg_sz;
    out->data_mem_off = dm;
    out->total_size = dm + data_seg_sz + bss_seg_sz;

    if (!parse_mod0(out))
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    return 0;
}

Result elfLoadNupModules(ModuleSet* set, NupArchive* nup,
                         const NupFileInfo* exefs, u32 exefs_count) {
    memset(set, 0, sizeof(*set));

    NupFileInfo sorted[MAX_LOADED_MODULES];
    u32 n = 0;
    for (u32 i = 0; i < exefs_count; i++) {
        if (nso_rank(exefs[i].name) >= 99)
            continue;
        if (n >= MAX_LOADED_MODULES)
            return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
        sorted[n++] = exefs[i];
    }
    if (n == 0)
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);

    for (u32 i = 1; i < n; i++) {
        NupFileInfo key = sorted[i];
        u32 j = i;
        while (j > 0 && nso_before(&key, &sorted[j - 1])) {
            sorted[j] = sorted[j - 1];
            j--;
        }
        sorted[j] = key;
    }

    for (u32 i = 0; i < n; i++) {
        printf("  Mapping %-8s (%llu KB)...\n", sorted[i].name,
               (unsigned long long)(sorted[i].size / 1024));
        consoleUpdate(NULL);
        Result rc = load_one_nso(nup, &sorted[i], i, &set->mods[i]);
        if (R_FAILED(rc))
            return rc;
        set->count = i + 1;
    }
    return 0;
}

static u32 sysv_elf_hash(const char* name) {
    u32 h = 0;
    for (const unsigned char* p = (const unsigned char*)name; *p; p++) {
        h = (h << 4) + *p;
        const u32 g = h & 0xf0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static u64 lookup_in_module(const LoadedModule* mod, const char* name, bool* out_weak) {
    if (!mod || !mod->symtab || !mod->strtab || !name || !name[0])
        return 0;
    const Elf64_Sym* syms = (const Elf64_Sym*)mod->symtab;
    if (mod->sysv_hash_off) {
        const u32* ht = (const u32*)((const u8*)(uintptr_t)mod->nso_base + mod->sysv_hash_off);
        const u32 nbucket = ht[0];
        const u32 nchain = ht[1];
        if (nbucket > 0 && nchain <= mod->sym_count + 1) {
            const u32* buckets = ht + 2;
            const u32* chains = buckets + nbucket;
            const u32 hv = sysv_elf_hash(name);
            for (u32 i = buckets[hv % nbucket]; i != 0 && i < nchain && i < mod->sym_count; i = chains[i]) {
                if (syms[i].st_shndx == 0 || syms[i].st_value == 0 || syms[i].st_name >= mod->strsz)
                    continue;
                if (strcmp(mod->strtab + syms[i].st_name, name) == 0) {
                    if (out_weak) *out_weak = (ELF64_ST_BIND(syms[i].st_info) == STB_WEAK);
                    return mod->nso_base + syms[i].st_value;
                }
            }
            return 0;
        }
    }
    for (u32 i = 1; i < mod->sym_count; i++) {
        if (syms[i].st_shndx == 0 || syms[i].st_value == 0 || syms[i].st_name >= mod->strsz)
            continue;
        if (strcmp(mod->strtab + syms[i].st_name, name) == 0) {
            if (out_weak) *out_weak = (ELF64_ST_BIND(syms[i].st_info) == STB_WEAK);
            return mod->nso_base + syms[i].st_value;
        }
    }
    return 0;
}

static u64 find_symbol_impl(const ModuleSet* set, const char* name, bool skip_compat1) {
    if (!set || !name || !name[0])
        return 0;
    u64 weak_addr = 0;
    for (u32 m = 0; m < set->count; m++) {
        const LoadedModule* mod = &set->mods[m];
        if (skip_compat1 && mod->is_compat && strcmp(mod->name, "compat1") == 0)
            continue;
        bool is_weak = false;
        const u64 addr = lookup_in_module(mod, name, &is_weak);
        if (addr) {
            if (is_weak) {
                if (!weak_addr) weak_addr = addr;
            } else {
                return addr;
            }
        }
    }
    return weak_addr;
}

u64 elfFindSymbol(const ModuleSet* set, const char* name) {
    return find_symbol_impl(set, name, false);
}

u64 elfFindSymbolSkipCompat1(const ModuleSet* set, const char* name) {
    return find_symbol_impl(set, name, true);
}

typedef struct {
    struct {
        const void* ptr;
        s32 size;
        u32 pad;
    } regions[11];
    s32 region_count;
    u32 pad_b4;
    u64 graphics_ctl;
    u64 movie_ctl;
    u64 audio_ctl;
    u64 misc_ctl;
} NupCompatParam;

_Static_assert(sizeof(NupCompatParam) == 0xd8, "NupCompatParam size");

static alignas(16) NupCompatParam g_compat_param;
static const NupCompatParam* g_kernel_compat_param = NULL;
static bool g_compat_params_inited = false;
static bool g_compat_ctors_ran = false;
static alignas(16) u8 g_dummy_runtime_obj[64];

static void stub_protect_relro(const void* a, const void* b, const void* c, const void* d, const void* e) {
    (void)a; (void)b; (void)c; (void)d; (void)e;
}

static bool stub_false(void) {
    return false;
}

static void unresolved_plt_stub(void) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogf("!!! CALLED UNRESOLVED PLT STUB from caller=0x%016llx\n", (unsigned long long)caller);
    svcBreak(BreakReason_Panic, caller, 0);
}

bool elfAttachSwitch1Compat(ModuleSet* set, u64 target_tid) {
    if (!set || (target_tid >> 56) != 0x01)
        return false;
    u64 host_pid = 0;
    svcGetInfo(&host_pid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
    if ((host_pid >> 56) != 0x01) {
        nupLogf("[compat] target=%016llx is Switch 1, but host=%016llx is Switch 2 (no CompatibilityPack mapped)\n",
                (unsigned long long)target_tid, (unsigned long long)host_pid);
        return false;
    }

    g_kernel_compat_param = NULL;
    g_compat_params_inited = false;
    g_compat_ctors_ran = false;
    LoadedModule compat1 = {}, compat2 = {};
    bool got_c1 = false, got_c2 = false;
    const u64 self_pc = (u64)(uintptr_t)&elfAttachSwitch1Compat;

    u64 addr = 0;
    for (int iter = 0; iter < 512; iter++) {
        MemoryInfo mi = {};
        u32 pi = 0;
        if (R_FAILED(svcQueryMemory(&mi, &pi, addr)) || mi.size == 0)
            break;
        const u64 next = mi.addr + mi.size;
        if (next <= addr)
            break;
        addr = next;

        // Check standalone CodeStatic RO pages for kernel's CompatibilityParameter record
        if (mi.type == 3 && mi.perm == 1 && mi.size <= 0x10000) {
            const u64 cand_ptr = *(const u64*)(uintptr_t)(mi.addr + 8);
            if (cand_ptr >= mi.addr && cand_ptr + sizeof(NupCompatParam) <= mi.addr + mi.size) {
                const NupCompatParam* cp = (const NupCompatParam*)(uintptr_t)cand_ptr;
                if (cp->region_count >= 0 && cp->region_count <= 11) {
                    g_kernel_compat_param = cp;
                    nupLogf("[compat] found kernel CompatParam @ 0x%llx (regions=%d gfx=0x%llx mov=0x%llx aud=0x%llx misc=0x%llx)\n",
                            (unsigned long long)cand_ptr, cp->region_count,
                            (unsigned long long)cp->graphics_ctl, (unsigned long long)cp->movie_ctl,
                            (unsigned long long)cp->audio_ctl, (unsigned long long)cp->misc_ctl);
                }
            }
            continue;
        }

        if (mi.type != 3 || mi.perm != 5 || mi.size < 0x1000)
            continue;
        if (self_pc >= mi.addr && self_pc < mi.addr + mi.size)
            continue;
        bool already_loaded = false;
        for (u32 m = 0; m < set->count; m++) {
            if (mi.addr >= set->mods[m].nro_base &&
                mi.addr < set->mods[m].nso_base + set->mods[m].total_size) {
                already_loaded = true;
                break;
            }
        }
        if (already_loaded)
            continue;

        MemoryInfo mi_ro = {}, mi_rw = {};
        u32 pi2 = 0;
        if (R_FAILED(svcQueryMemory(&mi_ro, &pi2, mi.addr + mi.size)) ||
            mi_ro.type != 3 || mi_ro.perm != 1)
            continue;
        if (R_FAILED(svcQueryMemory(&mi_rw, &pi2, mi_ro.addr + mi_ro.size)) ||
            mi_rw.type != 4 || (mi_rw.perm & 3) != 3)
            continue;

        // Check if another CodeMutable region immediately follows (.data + .bss split)
        u64 rw_end = mi_rw.addr + mi_rw.size;
        MemoryInfo mi_rw2 = {};
        if (R_SUCCEEDED(svcQueryMemory(&mi_rw2, &pi2, rw_end)) &&
            mi_rw2.addr == rw_end && mi_rw2.type == 4 && (mi_rw2.perm & 3) == 3) {
            rw_end += mi_rw2.size;
        }

        LoadedModule cand = {};
        cand.is_compat = true;
        cand.nro_base = mi.addr;
        cand.nso_base = mi.addr;
        cand.rodata_off = mi_ro.addr - mi.addr;
        cand.rodata_size = mi_ro.size;
        cand.data_mem_off = mi_rw.addr - mi.addr;
        cand.total_size = rw_end - mi.addr;
        if (!parse_mod0(&cand))
            continue;

        bool dummy_weak = false;
        if (lookup_in_module(&cand, "_ZN2nn6compat6detail25SetCompatibilityParameterEPNS0_22CompatibilityParameterE", &dummy_weak)) {
            snprintf(cand.name, sizeof(cand.name), "compat1");
            compat1 = cand;
            got_c1 = true;
            nupLogf("[compat] discovered compat1 (nnCompatThin) @ %016llx size=0x%llx syms=%u\n",
                    (unsigned long long)cand.nso_base, (unsigned long long)cand.total_size, cand.sym_count);
            addr = rw_end;
        } else if (lookup_in_module(&cand, "_ZN2nn2ro25LookupNextSymbolForCompatEPmPKc", &dummy_weak)) {
            snprintf(cand.name, sizeof(cand.name), "compat2");
            compat2 = cand;
            got_c2 = true;
            nupLogf("[compat] discovered compat2 (nnCompat) @ %016llx size=0x%llx syms=%u\n",
                    (unsigned long long)cand.nso_base, (unsigned long long)cand.total_size, cand.sym_count);
            addr = rw_end;
        } else {
            nupLogf("[compat] skipping host CodeStatic NSO @ %016llx size=0x%llx syms=%u\n",
                    (unsigned long long)cand.nso_base, (unsigned long long)cand.total_size, cand.sym_count);
            addr = rw_end;
        }
    }

    if (!got_c1 || !got_c2 || set->count + 2 > MAX_LOADED_MODULES) {
        nupLogf("[compat] attach incomplete: got_c1=%d got_c2=%d count=%u\n",
                got_c1 ? 1 : 0, got_c2 ? 1 : 0, set->count);
        return false;
    }

    // Insert [compat1, compat2] immediately before sdk so:
    //  - symbol lookup order is: main -> subsdk* -> compat1 -> compat2 -> sdk
    //  - init order (reverse) is: sdk -> compat2 -> compat1 -> subsdk* -> main
    u32 ins = set->count;
    if (ins > 0 && strcmp(set->mods[ins - 1].name, "sdk") == 0) {
        ins--;
        set->mods[ins + 2] = set->mods[ins];
    }
    set->mods[ins] = compat1;
    set->mods[ins + 1] = compat2;
    set->count += 2;
    set->has_compat = true;
    return true;
}

static u32 apply_relr(const LoadedModule* mod) {
    if (!mod->relr || !mod->relrsz)
        return 0;
    const u64 count = mod->relrsz / sizeof(u64);
    u64* where = NULL;
    u32 applied = 0;
    for (u64 i = 0; i < count; i++) {
        const u64 entry = mod->relr[i];
        if ((entry & 1) == 0) {
            where = (u64*)(uintptr_t)(mod->nso_base + entry);
            *where++ += mod->nso_base;
            applied++;
        } else if (where) {
            u64 bitmap = entry >> 1;
            for (u64 bit = 0; bitmap != 0; bit++, bitmap >>= 1) {
                if (bitmap & 1) {
                    where[bit] += mod->nso_base;
                    applied++;
                }
            }
            where += 63;
        }
    }
    return applied;
}

static void apply_rela_table(const ModuleSet* set, const LoadedModule* mod,
                             const Elf64_Rela* table, u64 bytes,
                             SymbolHookFn hook_fn, u32* unresolved, u32* logged_unres) {
    if (!table || bytes == 0)
        return;
    const Elf64_Sym* syms = (const Elf64_Sym*)mod->symtab;
    const u64 count = bytes / sizeof(Elf64_Rela);
    for (u64 i = 0; i < count; i++) {
        const u32 type = ELF64_R_TYPE(table[i].r_info);
        const u32 sym_idx = ELF64_R_SYM(table[i].r_info);
        const u64 off = table[i].r_offset;
        if (off < mod->data_mem_off || off + 8 > mod->total_size)
            continue;
        u64* slot = (u64*)(uintptr_t)(mod->nso_base + off);

        if (type == R_AARCH64_RELATIVE) {
            *slot = mod->nso_base + (u64)table[i].r_addend;
            continue;
        }
        if (type == R_AARCH64_TLSDESC) {
            if (off + 16 <= mod->total_size) {
                u64 tls_addr = 0;
                if (g_tls_cursor + 0x1000 <= sizeof(g_tls_fallback)) {
                    tls_addr = (u64)(uintptr_t)&g_tls_fallback[g_tls_cursor];
                    g_tls_cursor += 0x1000;
                } else {
                    tls_addr = (u64)(uintptr_t)&g_tls_fallback[0];
                }
                slot[0] = (u64)(uintptr_t)tlsdesc_resolver;
                slot[1] = tls_addr + (u64)table[i].r_addend;
                nupLogf("  reloc TLSDESC in %s @ +0x%llx -> buf=%016llx\n",
                        mod->name, (unsigned long long)off, (unsigned long long)slot[1]);
            }
            continue;
        }
        if (type != R_AARCH64_ABS64 && type != R_AARCH64_GLOB_DAT &&
            type != R_AARCH64_JUMP_SLOT) {
            nupLogf("  WARN unhandled reloc type=%u in %s @ +0x%llx\n",
                    type, mod->name, (unsigned long long)off);
            continue;
        }

        if (sym_idx >= mod->sym_count)
            continue;
        const Elf64_Sym* sym = &syms[sym_idx];
        const char* name = (sym->st_name < mod->strsz) ? (mod->strtab + sym->st_name) : "";
        u64 addr = 0;
        if (name[0]) {
            const bool is_c1_undef = mod->is_compat && strcmp(mod->name, "compat1") == 0 && sym->st_shndx == 0;
            if (strcmp(name, "_ZN2nn2ro25LookupNextSymbolForCompatEPmPKc") == 0) {
                addr = (u64)(uintptr_t)hooksLookupNextForCompat;
            } else if (strcmp(name, "_ZN2nn2ro12ProtectRelroEPKvS2_S2_S2_S2_") == 0) {
                addr = (u64)(uintptr_t)stub_protect_relro;
            } else {
                addr = is_c1_undef ? elfFindSymbolSkipCompat1(set, name) : elfFindSymbol(set, name);
                if (!addr) {
                    if (strcmp(name, "_ZN2nn2os18SdkAllocateTlsSlotEPNS0_7TlsSlotEPFvmE") == 0)
                        addr = elfFindSymbolSkipCompat1(set, "_ZN2nn2os15AllocateTlsSlotEPNS0_7TlsSlotEPFvmE");
                    else if (strcmp(name, "nnosLockMutex") == 0)
                        addr = elfFindSymbolSkipCompat1(set, "_ZN2nn2os9LockMutexEPNS0_9MutexTypeE");
                    else if (strcmp(name, "nnosUnlockMutex") == 0)
                        addr = elfFindSymbolSkipCompat1(set, "_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE");
                    else if (strcmp(name, "nnosInitializeMutex") == 0)
                        addr = elfFindSymbolSkipCompat1(set, "_ZN2nn2os15InitializeMutexEPNS0_9MutexTypeEbi");
                    else if (strcmp(name, "__nnDetailNintendoSdkRuntimeObjectFile") == 0 ||
                             strcmp(name, "_ZN2nn5album14g_LibraryStateE") == 0)
                        addr = (u64)(uintptr_t)g_dummy_runtime_obj;
                    else if (strcmp(name, "_ZN2nn6socket13IsInitializedEv") == 0)
                        addr = (u64)(uintptr_t)stub_false;
                }
                if (hook_fn) {
                    const u64 real_for_hook = set->has_compat ? elfFindSymbolSkipCompat1(set, name) : addr;
                    const u64 hooked = hook_fn(name, real_for_hook ? real_for_hook : addr);
                    if (hooked)
                        addr = hooked;
                }
            }
        } else if (sym->st_shndx != 0) {
            addr = mod->nso_base + sym->st_value;
        }

        if (!addr && ELF64_ST_BIND(sym->st_info) != STB_WEAK) {
            if (unresolved)
                (*unresolved)++;
            if (logged_unres && *logged_unres < 20) {
                (*logged_unres)++;
                nupLogf("  unresolved[%u] in %s: %s\n", *logged_unres, mod->name, name);
            }
            if (type == R_AARCH64_JUMP_SLOT)
                *slot = (u64)(uintptr_t)unresolved_plt_stub;
            continue;
        }
        if (type == R_AARCH64_ABS64)
            *slot = addr + (u64)table[i].r_addend;
        else
            *slot = addr;
    }
}

// rtld ModuleObject layouts (Switch 1 oss-rtld & Switch 2 SDK 20+)
typedef struct NupModObj {
    struct NupModObj* next;
    struct NupModObj* prev;
    void* rela_or_rel_plt;
    void* rela_or_rel;
    u8* module_base;
    void* dynamic;
    u64 is_rela;
    u64 rela_or_rel_plt_size;
    void (*dt_init)(void);
    void (*dt_fini)(void);
    u32* hash_bucket;
    u32* hash_chain;
    char* dynstr;
    void* dynsym;
    u64 dynstr_size;
    void** got;
    u64 rela_dyn_size, rel_dyn_size, rel_count, rela_count, hash_nchain, hash_nbucket;
    void* got_stub_ptr;
} NupModObj;

typedef struct {
    NupModObj* next;
    NupModObj* prev;
    void* rela_plt;
    void* rela;
    void* rel;
    u8* module_base;
    void* dynamic;
    u64 rela_plt_size;
    void (*dt_init)(void);
    void (*dt_fini)(void);
    void* hash_bucket;
    u64 hash_chain;
    char* dynstr;
    void* dynsym;
    u64 dynstr_size;
    void** got;
    u64 rela_dyn_size, rel_dyn_size, rel_count, rela_count;
    u64 hash_nchain;
    u64 hash_nbucket;
    u64 soname;
    u64 size;
    u8 sdk, pad[2], flags;
    u32 pad2;
    u64 stub;
} NupModObj20;

static struct { NupModObj* next; NupModObj* prev; } g_auto_load_list;
static struct { void* next; void* prev; } g_manual_load_list;
static void* g_manual_lookup = NULL;
static u8 g_ro_debug_flag = 0;
static const ModuleSet* g_active_set = NULL;

static u64 rtld_auto_lookup(const char* name) {
    if (!g_active_set || !name) return 0;
    return elfFindSymbol(g_active_set, name);
}

static void init_module_object(const LoadedModule* mod) {
    if (!mod->module_object_off || mod->module_object_off < mod->data_mem_off)
        return;
    const u8* base = (const u8*)(uintptr_t)mod->nso_base;
    const u32 first_word = *(const u32*)base;
    if (first_word == 1 && mod->module_object_off + sizeof(NupModObj20) <= mod->total_size) {
        NupModObj20* o = (NupModObj20*)(uintptr_t)(mod->nso_base + mod->module_object_off);
        memset(o, 0, sizeof(*o));
        o->module_base = (u8*)(uintptr_t)mod->nso_base;
        o->dynamic = (void*)(uintptr_t)(mod->nso_base + mod->dynamic_off);
        o->rela = (void*)mod->rela;
        o->rela_dyn_size = mod->relasz;
        o->rela_count = mod->relacount;
        o->rela_plt = (void*)mod->jmprel;
        o->rela_plt_size = mod->pltrelsz;
        o->dt_init = (void (*)(void))(uintptr_t)mod->init_fn;
        o->dt_fini = (void (*)(void))(uintptr_t)mod->fini_fn;
        o->sdk = 20;
        o->flags = 2 | 4;
        if (mod->gnu_hash_off) {
            const u32* h = (const u32*)(base + mod->gnu_hash_off);
            o->hash_bucket = (void*)(h + 4);
            o->hash_chain = h[2];
            o->hash_nchain = h[3];
            o->hash_nbucket = (u64)(uintptr_t)h;
            o->flags |= 16;
        } else if (mod->sysv_hash_off) {
            const u32* h = (const u32*)(base + mod->sysv_hash_off);
            o->hash_nbucket = h[0];
            o->hash_nchain = h[1];
            o->hash_bucket = (void*)(h + 2);
            o->hash_chain = (u64)(uintptr_t)(h + 2 + h[0]);
        }
        o->dynstr = (char*)mod->strtab;
        o->dynstr_size = mod->strsz;
        o->dynsym = (void*)mod->symtab;
        o->got = mod->pltgot_off ? (void**)(uintptr_t)(mod->nso_base + mod->pltgot_off) : NULL;
        o->prev = g_auto_load_list.prev;
        o->next = (NupModObj*)&g_auto_load_list;
        g_auto_load_list.prev->next = (NupModObj*)o;
        g_auto_load_list.prev = (NupModObj*)o;
    } else if (mod->module_object_off + sizeof(NupModObj) <= mod->total_size) {
        NupModObj* o = (NupModObj*)(uintptr_t)(mod->nso_base + mod->module_object_off);
        memset(o, 0, sizeof(*o));
        o->module_base = (u8*)(uintptr_t)mod->nso_base;
        o->dynamic = (void*)(uintptr_t)(mod->nso_base + mod->dynamic_off);
        o->is_rela = 1;
        o->rela_or_rel = (void*)mod->rela;
        o->rela_dyn_size = mod->relasz;
        o->rela_count = mod->relacount;
        o->rela_or_rel_plt = (void*)mod->jmprel;
        o->rela_or_rel_plt_size = mod->pltrelsz;
        o->dt_init = (void (*)(void))(uintptr_t)mod->init_fn;
        o->dt_fini = (void (*)(void))(uintptr_t)mod->fini_fn;
        if (mod->sysv_hash_off) {
            const u32* h = (const u32*)(base + mod->sysv_hash_off);
            o->hash_nbucket = h[0];
            o->hash_nchain = h[1];
            o->hash_bucket = (u32*)(h + 2);
            o->hash_chain = (u32*)(h + 2 + h[0]);
        }
        o->dynstr = (char*)mod->strtab;
        o->dynstr_size = mod->strsz;
        o->dynsym = (void*)mod->symtab;
        o->got = mod->pltgot_off ? (void**)(uintptr_t)(mod->nso_base + mod->pltgot_off) : NULL;
        o->prev = g_auto_load_list.prev;
        o->next = (NupModObj*)&g_auto_load_list;
        g_auto_load_list.prev->next = o;
        g_auto_load_list.prev = o;
    }
}

Result elfRelocateAll(ModuleSet* set, SymbolHookFn hook_fn, u32* out_unresolved) {
    u32 unresolved = 0;
    u32 logged_unres = 0;
    g_active_set = set;
    g_auto_load_list.next = g_auto_load_list.prev = (NupModObj*)&g_auto_load_list;
    g_manual_load_list.next = g_manual_load_list.prev = &g_manual_load_list;
    g_manual_lookup = NULL;
    g_ro_debug_flag = 0;
    for (u32 m = 0; m < set->count; m++) {
        const LoadedModule* mod = &set->mods[m];
        const u32 relr_n = apply_relr(mod);
        nupLogf("reloc %s: base=%016llx syms=%u relr=%u rela=%llu jmprel=%llu init=%016llx init_arr=%llu\n",
                mod->name, (unsigned long long)mod->nso_base, mod->sym_count, relr_n,
                (unsigned long long)(mod->relasz / sizeof(Elf64_Rela)),
                (unsigned long long)(mod->pltrelsz / sizeof(Elf64_Rela)),
                (unsigned long long)mod->init_fn,
                (unsigned long long)(mod->init_arraysz / sizeof(u64)));
        apply_rela_table(set, mod, (const Elf64_Rela*)mod->rela, mod->relasz,
                         hook_fn, &unresolved, &logged_unres);
        apply_rela_table(set, mod, (const Elf64_Rela*)mod->jmprel, mod->pltrelsz,
                         hook_fn, &unresolved, &logged_unres);
        init_module_object(mod);
    }
    // Wire up rtld's nn::ro::detail globals so nn::ro / unwinder never dereference NULL
    void** p;
    if ((p = (void**)(uintptr_t)elfFindSymbol(set, "_ZN2nn2ro6detail15g_pAutoLoadListE"))) *p = &g_auto_load_list;
    if ((p = (void**)(uintptr_t)elfFindSymbol(set, "_ZN2nn2ro6detail17g_pManualLoadListE"))) *p = &g_manual_load_list;
    if ((p = (void**)(uintptr_t)elfFindSymbol(set, "_ZN2nn2ro6detail34g_pLookupGlobalAutoFunctionPointerE"))) *p = (void*)rtld_auto_lookup;
    if ((p = (void**)(uintptr_t)elfFindSymbol(set, "_ZN2nn2ro6detail36g_pLookupGlobalManualFunctionPointerE"))) *p = &g_manual_lookup;
    if ((p = (void**)(uintptr_t)elfFindSymbol(set, "_ZN2nn2ro6detail14g_pRoDebugFlagE"))) *p = &g_ro_debug_flag;
    if (out_unresolved)
        *out_unresolved = unresolved;
    return 0;
}

const char* elfAddrToSymbol(const ModuleSet* set, u64 addr, u64* out_off) {
    if (!set)
        return NULL;
    const char* best = NULL;
    u64 bv = 0;
    for (u32 m = 0; m < set->count; m++) {
        const LoadedModule* mod = &set->mods[m];
        if (!mod->symtab || !mod->strtab)
            continue;
        if (addr < mod->nso_base || addr >= mod->nso_base + mod->total_size)
            continue;
        const Elf64_Sym* s = (const Elf64_Sym*)mod->symtab;
        for (u32 i = 1; i < mod->sym_count; i++) {
            if (!s[i].st_shndx || !s[i].st_value || s[i].st_name >= mod->strsz)
                continue;
            if ((s[i].st_info & 0xf) != 2) /* STT_FUNC */
                continue;
            const u64 a = mod->nso_base + s[i].st_value;
            if (a <= addr && a > bv && (!s[i].st_size || addr < a + s[i].st_size)) {
                bv = a;
                best = mod->strtab + s[i].st_name;
            }
        }
    }
    if (best && out_off)
        *out_off = addr - bv;
    return best;
}

void elfLogMatchingSymbols(const ModuleSet* set, const char* substr) {
    if (!set || !substr || !substr[0])
        return;
    u32 hits = 0;
    nupLogf("[symscan] searching for '%s':\n", substr);
    for (u32 m = 0; m < set->count; m++) {
        const LoadedModule* mod = &set->mods[m];
        if (!mod->symtab || !mod->strtab)
            continue;
        const Elf64_Sym* syms = (const Elf64_Sym*)mod->symtab;
        for (u32 i = 0; i < mod->sym_count; i++) {
            if (syms[i].st_shndx == 0 || syms[i].st_name >= mod->strsz)
                continue;
            const char* name = mod->strtab + syms[i].st_name;
            if (strstr(name, substr)) {
                if (hits < 16) {
                    nupLogf("  [%s] %s @ %016llx\n", mod->name, name,
                            (unsigned long long)(mod->nso_base + syms[i].st_value));
                }
                hits++;
            }
        }
    }
    nupLogf("[symscan] '%s' total=%u\n", substr, hits);
}

void elfInitSwitch1CompatParams(const ModuleSet* set) {
    if (!set || !set->has_compat || g_compat_params_inited)
        return;
    g_compat_params_inited = true;
    memset(&g_compat_param, 0, sizeof(g_compat_param));
    if (g_kernel_compat_param) {
        g_compat_param.graphics_ctl = g_kernel_compat_param->graphics_ctl;
        g_compat_param.movie_ctl = g_kernel_compat_param->movie_ctl;
        g_compat_param.audio_ctl = g_kernel_compat_param->audio_ctl;
        g_compat_param.misc_ctl = g_kernel_compat_param->misc_ctl;
    }
    s32 rcnt = 0;
    for (u32 m = 0; m < set->count && rcnt < 11; m++) {
        const LoadedModule* mod = &set->mods[m];
        if (mod->is_compat || !mod->rodata_size)
            continue;
        g_compat_param.regions[rcnt].ptr = (const void*)(uintptr_t)(mod->nso_base + mod->rodata_off);
        g_compat_param.regions[rcnt].size = (mod->rodata_size > 0x7fffffffULL) ? 0x7fffffff : (s32)mod->rodata_size;
        rcnt++;
    }
    g_compat_param.region_count = rcnt;

    const u64 set_param_fn = elfFindSymbol(set, "_ZN2nn6compat6detail25SetCompatibilityParameterEPNS0_22CompatibilityParameterE");
    const u64 extract_ver_fn = elfFindSymbol(set, "_ZN2nn6compat6detail26ExtractSdkVersionForCompatEv");
    const u64 set_ver_fn = elfFindSymbol(set, "_ZN2nn6compat6detail22SetSdkVersionForCompatERKNS0_10SdkVersionE");
    if (set_param_fn) {
        ((void (*)(NupCompatParam*))(uintptr_t)set_param_fn)(&g_compat_param);
    }
    if (extract_ver_fn && set_ver_fn) {
        typedef struct { u32 major, minor, patch, extra; } CompatSdkVer;
        const CompatSdkVer ver = ((CompatSdkVer (*)(void))(uintptr_t)extract_ver_fn)();
        ((void (*)(const CompatSdkVer*))(uintptr_t)set_ver_fn)(&ver);
        nupLogf("[compat] SetCompatibilityParameter(regions=%d) SdkVersion=%u.%u.%u (%u) ctl=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
                rcnt, ver.major, ver.minor, ver.patch, ver.extra,
                (unsigned long long)g_compat_param.graphics_ctl,
                (unsigned long long)g_compat_param.movie_ctl,
                (unsigned long long)g_compat_param.audio_ctl,
                (unsigned long long)g_compat_param.misc_ctl);
    }
}

void elfRunCompatInitArrays(ModuleSet* set) {
    if (!set || !set->has_compat || g_compat_ctors_ran)
        return;
    g_compat_ctors_ran = true;
    // Run compat2 then compat1 DT_INIT_ARRAY before nninitInitializeSdkModule invokes
    // compat2's nn::oe::InitializeApplet (which uses compat2's static MemoryResource vtable
    // and mutexes initialized by compat2's DT_INIT_ARRAY, e.g. 0x1438a0 / 0x147968).
    for (s32 m = (s32)set->count - 1; m >= 0; m--) {
        const LoadedModule* mod = &set->mods[m];
        if (!mod->is_compat)
            continue;
        if (mod->init_array && mod->init_arraysz > 0) {
            const u64 count = mod->init_arraysz / sizeof(u64);
            nupLogf("[compat] init %s DT_INIT_ARRAY (%llu entries, first=%016llx)\n",
                    mod->name, (unsigned long long)count,
                    (unsigned long long)(count ? mod->init_array[0] : 0));
            for (u64 i = 0; i < count; i++) {
                const u64 fn_addr = mod->init_array[i];
                if (fn_addr && fn_addr != ~(u64)0) {
                    ((void (*)(void))(uintptr_t)fn_addr)();
                }
            }
            u64 used_now = 0;
            svcGetInfo(&used_now, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
            nupLogf("[compat] init %s done (used=0x%llx)\n", mod->name, (unsigned long long)used_now);
        }
    }
}

void elfRunInitArrays(const ModuleSet* set, void (*after_sdk_cb)(void)) {
    for (s32 m = (s32)set->count - 1; m >= 0; m--) {
        const LoadedModule* mod = &set->mods[m];
        if (mod->is_compat && g_compat_ctors_ran)
            continue;
        if (mod->init_fn && !mod->is_compat) {
            // A module's DT_INIT (SDK CRT) already executes its DT_INIT_ARRAY via
            // __nnmusl_init_dso; running DT_INIT_ARRAY again invokes every constructor twice!
            // For Switch 2 compat1/compat2 modules inside a Switch 1 process, skip DT_INIT
            // (avoids Switch 2 9-arg __nnmusl_init_dso ABI mismatch + ProtectRelro) and run DT_INIT_ARRAY directly.
            nupLogf("init %s DT_INIT @ %016llx (handles %llu init_arr entries)\n",
                    mod->name, (unsigned long long)mod->init_fn,
                    (unsigned long long)(mod->init_arraysz / sizeof(u64)));
            ((void (*)(void))(uintptr_t)mod->init_fn)();
        } else if (mod->init_array && mod->init_arraysz > 0) {
            const u64 count = mod->init_arraysz / sizeof(u64);
            nupLogf("init %s DT_INIT_ARRAY (%llu entries, first=%016llx)\n",
                    mod->name, (unsigned long long)count,
                    (unsigned long long)(count ? mod->init_array[0] : 0));
            for (u64 i = 0; i < count; i++) {
                const u64 fn_addr = mod->init_array[i];
                if (fn_addr && fn_addr != ~(u64)0) {
                    ((void (*)(void))(uintptr_t)fn_addr)();
                }
            }
        }
        {
            u64 used_now = 0;
            svcGetInfo(&used_now, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
            nupLogf("init %s done (used=0x%llx)\n", mod->name, (unsigned long long)used_now);
        }
        if (strcmp(mod->name, "sdk") == 0) {
            elfInitSwitch1CompatParams(set);
            if (after_sdk_cb)
                after_sdk_cb();
        }
    }
}
