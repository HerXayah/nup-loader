// SPDX-License-Identifier: MIT
#include "native_boot.h"
#include "log.h"
#include "nup.h"
#include "nupvfs_proto.h"
#include "romfs_subsdk_nso.h"
#include "zbic.h"

#include <kaihen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUP_SVC_HOOK_MAGIC0 0x56535F50554E5353ull /* "SSNUP_SV" */
#define NUP_SVC_HOOK_MAGIC1 0x314B4F4F485F4353ull /* "SC_HOOK1" */

typedef struct {
    u64 magic0;
    u64 magic1;
    u64 entry_fn;
    u64 reserved;
} NupSvcHookSlot;

static u32 page_align32(u32 v) {
    return (v + 0xFFFu) & ~0xFFFu;
}

static bool lz4_decompress_block(const u8* src, u32 src_len, u8* dst, u32 dst_len) {
    u32 sp = 0, dp = 0;
    while (sp < src_len) {
        const u8 tok = src[sp++];
        u32 lit = tok >> 4;
        if (lit == 15) {
            u8 b;
            do { if (sp >= src_len) return false; b = src[sp++]; lit += b; } while (b == 255);
        }
        if (sp + lit > src_len || dp + lit > dst_len) return false;
        memcpy(dst + dp, src + sp, lit);
        sp += lit; dp += lit;
        if (sp >= src_len) break;
        if (sp + 2 > src_len) return false;
        const u32 off = (u32)src[sp] | ((u32)src[sp + 1] << 8);
        sp += 2;
        if (off == 0 || off > dp) return false;
        u32 mlen = (tok & 0x0Fu) + 4u;
        if (mlen == 19u) {
            u8 b;
            do { if (sp >= src_len) return false; b = src[sp++]; mlen += b; } while (b == 255);
        }
        if (dp + mlen > dst_len) return false;
        for (u32 i = 0; i < mlen; i++) dst[dp + i] = dst[dp - off + i];
        dp += mlen;
    }
    return dp == dst_len;
}

// Decompresses an NSO (LZ4 or ZBIC) and appends:
//   - 1 extra .text page with ASLR-safe 44-byte SVC thunks (fallback to raw svc while entry_fn == 0)
//   - 1 extra .data page holding NupSvcHookSlot (found & bound by romfs-subsdk constructor)
static bool build_patched_sdk_nso(const u8* in_nso, u64 in_sz, u8** out_buf, u64* out_sz) {
    if (!in_nso || in_sz < 0x100 || memcmp(in_nso, "NSO0", 4) != 0)
        return false;

    u32 flags = 0;
    u32 tf, tm, ts, rf, rm, rs, df, dm, ds, bss;
    u32 tc, rc_sz, dc;
    memcpy(&flags, in_nso + 0x0c, 4);
    memcpy(&tf, in_nso + 0x10, 4); memcpy(&tm, in_nso + 0x14, 4); memcpy(&ts, in_nso + 0x18, 4);
    memcpy(&rf, in_nso + 0x20, 4); memcpy(&rm, in_nso + 0x24, 4); memcpy(&rs, in_nso + 0x28, 4);
    memcpy(&df, in_nso + 0x30, 4); memcpy(&dm, in_nso + 0x34, 4); memcpy(&ds, in_nso + 0x38, 4);
    memcpy(&bss, in_nso + 0x3c, 4);
    memcpy(&tc, in_nso + 0x60, 4); memcpy(&rc_sz, in_nso + 0x64, 4); memcpy(&dc, in_nso + 0x68, 4);

    if (tm != 0 || rm == 0 || dm <= rm || (u64)ds + (u64)bss > 0x4000000ull)
        return false;

    // Place NupSvcHookSlot AFTER .bss so sdk's zero-initialized globals are never stomped.
    const u32 slot_in_data = (ds + bss + 15u) & ~15u;
    const u32 new_ds = slot_in_data + (u32)sizeof(NupSvcHookSlot);
    const u32 slot_vaddr = dm + slot_in_data;
    const u32 new_bss = 0u;

    u8* text_raw = (u8*)calloc(1, page_align32(ts) + 0x1000u);
    u8* ro_raw   = (u8*)calloc(1, rs ? rs : 1);
    u8* data_raw = (u8*)calloc(1, new_ds);
    if (!text_raw || !ro_raw || !data_raw) {
        free(text_raw); free(ro_raw); free(data_raw);
        return false;
    }

    const bool is_zbic = (flags & 0x80u) != 0;
    const u32 foffs[3] = { tf, rf, df };
    const u32 dsizes[3] = { ts, rs, ds };
    const u32 csizes[3] = { tc, rc_sz, dc };
    u8* dsts[3] = { text_raw, ro_raw, data_raw };

    for (int s = 0; s < 3; s++) {
        if (dsizes[s] == 0) continue;
        if (flags & (1u << s)) {
            if ((u64)foffs[s] + csizes[s] > in_sz) { free(text_raw); free(ro_raw); free(data_raw); return false; }
            const bool ok = is_zbic
                ? zbicDecompress(dsts[s], dsizes[s], in_nso + foffs[s], csizes[s])
                : lz4_decompress_block(in_nso + foffs[s], csizes[s], dsts[s], dsizes[s]);
            if (!ok) { free(text_raw); free(ro_raw); free(data_raw); return false; }
        } else {
            if ((u64)foffs[s] + dsizes[s] > in_sz) { free(text_raw); free(ro_raw); free(data_raw); return false; }
            memcpy(dsts[s], in_nso + foffs[s], dsizes[s]);
        }
    }

    // Count SVC sites (skip 0x36 SynchronizePreemptionState)
    u32 svc_cnt = 0;
    for (u32 off = 0; off + 4 <= ts; off += 4) {
        u32 w = 0;
        memcpy(&w, text_raw + off, 4);
        if ((w & 0xFFE0001Fu) == 0xD4000001u && ((w >> 5) & 0xFFFFu) != 0x36u)
            svc_cnt++;
    }

    // Place thunks in existing .text tail slack if it fits, else fail gracefully (Loader keeps rm fixed)
    const u32 thunk_bytes = svc_cnt * 44u;
    const u32 slack_start = (ts + 7u) & ~7u;
    if (slack_start + thunk_bytes > rm) {
        nupLogf("[native-boot] sdk .text slack too small (%u < %u for %u SVCs)\n",
                rm - slack_start, thunk_bytes, svc_cnt);
        free(text_raw); free(ro_raw); free(data_raw);
        return false;
    }

    // NupSvcHookSlot lives at slot_in_data (after .data + zero-filled .bss)
    NupSvcHookSlot slot = {
        .magic0 = NUP_SVC_HOOK_MAGIC0,
        .magic1 = NUP_SVC_HOOK_MAGIC1,
        .entry_fn = 0,
        .reserved = 0,
    };
    memcpy(data_raw + slot_in_data, &slot, sizeof(slot));

    // Patch every svc #n in .text -> 11-instruction ASLR-safe thunk using ADRP+LDR to slot_vaddr+16
    u32 idx = 0;
    for (u32 off = 0; off + 4 <= ts; off += 4) {
        u32 w = 0;
        memcpy(&w, text_raw + off, 4);
        if ((w & 0xFFE0001Fu) != 0xD4000001u)
            continue;
        const u32 imm = (w >> 5) & 0xFFFFu;
        if (imm == 0x36u)
            continue;

        const u32 here = slack_start + idx++ * 44u;
        const s64 b_to_thunk = ((s64)here - (s64)off) / 4;
        if (b_to_thunk >= 0x2000000ll || b_to_thunk < -0x2000000ll)
            continue;

        const u32 target_fn_va = slot_vaddr + 16u; // offsetof(NupSvcHookSlot, entry_fn)
        const u32 adrp_pc = here + 4u;
        const s64 page_delta = (s64)(target_fn_va >> 12) - (s64)(adrp_pc >> 12);
        const u32 immlo = (u32)(page_delta & 3ll);
        const u32 immhi = (u32)((page_delta >> 2) & 0x7FFFFll);
        const u32 page_off = target_fn_va & 0xFFFu;

        u32 t[11];
        t[0]  = 0xA9BF7BF0u;                                                // stp x16, x30, [sp, #-16]!
        t[1]  = 0x90000010u | (immlo << 29) | (immhi << 5);                 // adrp x16, slot_page
        t[2]  = 0xF940021Eu | ((page_off / 8u) << 10);                      // ldr x30, [x16, #page_off]
        t[3]  = 0xB500009Eu;                                                // cbnz x30, +16 (to t[7])
        t[4]  = 0xA8C17BF0u;                                                // ldp x16, x30, [sp], #16
        t[5]  = 0xD4000001u | (imm << 5);                                   // svc #imm (pre-ctor fallback)
        t[6]  = 0x14000000u | (u32)((((s64)(off + 4u) - (s64)(here + 24u)) / 4) & 0x3FFFFFFu); // b site+4
        t[7]  = 0x52800010u | (imm << 5);                                   // mov w16, #imm
        t[8]  = 0xD63F03C0u;                                                // blr x30
        t[9]  = 0xA8C17BF0u;                                                // ldp x16, x30, [sp], #16
        t[10] = 0x14000000u | (u32)((((s64)(off + 4u) - (s64)(here + 40u)) / 4) & 0x3FFFFFFu); // b site+4
        memcpy(text_raw + here, t, sizeof(t));

        const u32 b_insn = 0x14000000u | (u32)(b_to_thunk & 0x3FFFFFFu);
        memcpy(text_raw + off, &b_insn, 4);
    }

    const u32 new_ts = slack_start + thunk_bytes;
    const u32 new_tf = 0x100u;
    const u32 new_rf = new_tf + new_ts;
    const u32 new_df = new_rf + rs;
    const u64 total = (u64)new_df + new_ds;

    u8* nso = (u8*)malloc((size_t)total);
    if (!nso) {
        free(text_raw); free(ro_raw); free(data_raw);
        return false;
    }
    memcpy(nso, in_nso, 0x100);
    // Clear compressed + hash-check + ZBIC flags (uncompressed NSO0)
    const u32 new_flags = 0u;
    memcpy(nso + 0x0c, &new_flags, 4);
    memcpy(nso + 0x10, &new_tf, 4); memcpy(nso + 0x18, &new_ts, 4);
    memcpy(nso + 0x20, &new_rf, 4); memcpy(nso + 0x28, &rs, 4);
    memcpy(nso + 0x30, &new_df, 4); memcpy(nso + 0x38, &new_ds, 4);
    memcpy(nso + 0x3c, &new_bss, 4);
    memcpy(nso + 0x60, &new_ts, 4);
    memcpy(nso + 0x64, &rs, 4);
    memcpy(nso + 0x68, &new_ds, 4);
    memcpy(nso + new_tf, text_raw, new_ts);
    if (rs) memcpy(nso + new_rf, ro_raw, rs);
    memcpy(nso + new_df, data_raw, new_ds);

    free(text_raw); free(ro_raw); free(data_raw);
    *out_buf = nso;
    *out_sz = total;
    nupLogf("[native-boot] patched sdk NSO: %u SVC sites, slot_va=0x%x, out_sz=0x%llx\n",
            idx, slot_vaddr, (unsigned long long)total);
    return true;
}

static bool read_sd_whole(FsFileSystem* sd, const char* path, u8** out_buf, u64* out_sz) {
    FsFile f = {};
    if (R_FAILED(nupRawFsOpenFile(sd, path, FsOpenMode_Read, &f)))
        return false;
    s64 sz = 0;
    if (R_FAILED(nupRawFileGetSize(&f, &sz)) || sz <= 0) {
        serviceClose(&f.s);
        return false;
    }
    u8* buf = (u8*)malloc((size_t)sz);
    if (!buf) {
        serviceClose(&f.s);
        return false;
    }
    u64 done = 0;
    while (done < (u64)sz) {
        const u64 chunk = ((u64)sz - done) > 0x400000ull ? 0x400000ull : ((u64)sz - done);
        u64 got = 0;
        if (R_FAILED(nupRawFileRead(&f, (s64)done, buf + done, chunk, &got)) || got == 0) {
            free(buf);
            serviceClose(&f.s);
            return false;
        }
        done += got;
    }
    serviceClose(&f.s);
    *out_buf = buf;
    *out_sz = (u64)sz;
    return true;
}

typedef struct {
    char name[32];
    char sd_path[0x320]; // Non-empty when streamed directly from SD
    u8*  mem_buf;        // Non-NULL when written from RAM
    u64  size;
    u64  data_off;
    u32  name_off;
} PfsEntry;

static Result write_pfs0(FsFileSystem* sd, const char* out_path, PfsEntry* items, u32 count) {
    u32 str_sz = 0;
    for (u32 i = 0; i < count; i++) {
        items[i].name_off = str_sz;
        str_sz += (u32)strlen(items[i].name) + 1u;
    }
    const u32 str_aligned = (str_sz + 0x1Fu) & ~0x1Fu;
    const u64 hdr_sz = 16ull + (u64)count * 24ull + str_aligned;
    u64 data_pos = 0;
    for (u32 i = 0; i < count; i++) {
        items[i].data_off = data_pos;
        data_pos += (items[i].size + 0x1Fu) & ~0x1Full;
    }
    const u64 total_sz = hdr_sz + data_pos;

    u8* hdr = (u8*)calloc(1, (size_t)hdr_sz);
    if (!hdr)
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    memcpy(hdr, "PFS0", 4);
    memcpy(hdr + 4, &count, 4);
    memcpy(hdr + 8, &str_aligned, 4);
    for (u32 i = 0; i < count; i++) {
        u8* e = hdr + 16 + i * 24;
        memcpy(e + 0,  &items[i].data_off, 8);
        memcpy(e + 8,  &items[i].size, 8);
        memcpy(e + 16, &items[i].name_off, 4);
        memcpy(hdr + 16 + count * 24 + items[i].name_off, items[i].name, strlen(items[i].name) + 1);
    }

    nupRawFsDeleteFile(sd, out_path);
    Result rc = nupRawFsCreateFile(sd, out_path, (s64)total_sz, 0);
    if (R_FAILED(rc)) { free(hdr); return rc; }

    FsFile out = {};
    rc = nupRawFsOpenFile(sd, out_path, FsOpenMode_Write, &out);
    if (R_FAILED(rc)) { free(hdr); return rc; }

    rc = nupRawFileWrite(&out, 0, hdr, hdr_sz, FsWriteOption_None);
    free(hdr);

    u8* xfer = (u8*)malloc(0x100000);
    if (!xfer) { serviceClose(&out.s); return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory); }

    for (u32 i = 0; i < count && R_SUCCEEDED(rc); i++) {
        const u64 dst_base = hdr_sz + items[i].data_off;
        if (items[i].mem_buf) {
            u64 done = 0;
            while (done < items[i].size && R_SUCCEEDED(rc)) {
                const u64 chunk = (items[i].size - done) > 0x100000ull ? 0x100000ull : (items[i].size - done);
                rc = nupRawFileWrite(&out, (s64)(dst_base + done), items[i].mem_buf + done, chunk, FsWriteOption_None);
                done += chunk;
            }
        } else {
            FsFile in = {};
            rc = nupRawFsOpenFile(sd, items[i].sd_path, FsOpenMode_Read, &in);
            u64 done = 0;
            while (done < items[i].size && R_SUCCEEDED(rc)) {
                const u64 chunk = (items[i].size - done) > 0x100000ull ? 0x100000ull : (items[i].size - done);
                u64 got = 0;
                rc = nupRawFileRead(&in, (s64)done, xfer, chunk, &got);
                if (R_SUCCEEDED(rc) && got > 0)
                    rc = nupRawFileWrite(&out, (s64)(dst_base + done), xfer, got, FsWriteOption_None);
                done += got;
                if (got == 0) break;
            }
            serviceClose(&in.s);
        }
    }

    free(xfer);
    nupRawFileFlush(&out);
    serviceClose(&out.s);
    return rc;
}

Result nupArmNativeLoaderBoot(FsFileSystem* sd, const NupEntry* entry,
                              char* out_msg, size_t out_msg_sz) {
    if (!sd || !entry)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    // 1. Verify donor signed main.npdm and freestanding romfs-subsdk.nso
    u8* npdm_buf = NULL; u64 npdm_sz = 0;
    if (!read_sd_whole(sd, "/kaihen/bin/game/main.npdm", &npdm_buf, &npdm_sz)) {
        snprintf(out_msg, out_msg_sz, "missing /kaihen/bin/game/main.npdm");
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }
    // Optional SD override at /kaihen/bin/romfs-subsdk.nso; falls back to embedded NSO
    u8* subsdk_buf = NULL; u64 subsdk_sz = 0;
    bool subsdk_owned = true;
    if (!read_sd_whole(sd, "/kaihen/bin/romfs-subsdk.nso", &subsdk_buf, &subsdk_sz)) {
        subsdk_buf = (u8*)(uintptr_t)g_embedded_romfs_subsdk_nso;
        subsdk_sz = sizeof(g_embedded_romfs_subsdk_nso);
        subsdk_owned = false;
    }

    // 2. Discover ExeFS files in the RAW game folder
    NupArchive nup = {};
    NupFileInfo exefs[NUP_MAX_EXEFS_FILES];
    u32 exefs_cnt = 0;
    if (!nupProbeRaw(sd, entry->path, NULL, exefs, &exefs_cnt) ||
        R_FAILED(nupOpenRaw(&nup, sd, entry->path))) {
        free(npdm_buf); if (subsdk_owned) free(subsdk_buf);
        snprintf(out_msg, out_msg_sz, "failed to open RAW folder");
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }

    PfsEntry items[NUP_MAX_EXEFS_FILES + 4];
    memset(items, 0, sizeof(items));
    u32 item_cnt = 0;
    int max_subsdk = -1;
    u8* patched_sdk = NULL; u64 patched_sdk_sz = 0;

    // Add donor signed main.npdm first
    snprintf(items[item_cnt].name, sizeof(items[0].name), "main.npdm");
    items[item_cnt].mem_buf = npdm_buf;
    items[item_cnt].size = npdm_sz;
    item_cnt++;

    for (u32 i = 0; i < exefs_cnt && item_cnt < NUP_MAX_EXEFS_FILES + 2; i++) {
        if (strcmp(exefs[i].name, "main.npdm") == 0)
            continue;
        if (strncmp(exefs[i].name, "subsdk", 6) == 0 && exefs[i].name[6] >= '0' && exefs[i].name[6] <= '9') {
            const int n = atoi(exefs[i].name + 6);
            if (n > max_subsdk) max_subsdk = n;
        }
        char full[0x320];
        snprintf(full, sizeof(full), "%s/exefs/%s", nup.raw_root, exefs[i].name);
        if (strcmp(exefs[i].name, "sdk") == 0) {
            u8* raw_sdk = NULL; u64 raw_sdk_sz = 0;
            if (read_sd_whole(sd, full, &raw_sdk, &raw_sdk_sz)) {
                const bool patched = build_patched_sdk_nso(raw_sdk, raw_sdk_sz, &patched_sdk, &patched_sdk_sz);
                free(raw_sdk);
                if (patched) {
                    snprintf(items[item_cnt].name, sizeof(items[0].name), "sdk");
                    items[item_cnt].mem_buf = patched_sdk;
                    items[item_cnt].size = patched_sdk_sz;
                    item_cnt++;
                    continue;
                }
            }
        }
        snprintf(items[item_cnt].name, sizeof(items[0].name), "%.31s", exefs[i].name);
        snprintf(items[item_cnt].sd_path, sizeof(items[0].sd_path), "%s", full);
        items[item_cnt].size = exefs[i].size;
        item_cnt++;
    }

    // Inject our freestanding SVC-shim as subsdk<max_subsdk + 1>
    snprintf(items[item_cnt].name, sizeof(items[0].name), "subsdk%d", max_subsdk + 1);
    items[item_cnt].mem_buf = subsdk_buf;
    items[item_cnt].size = subsdk_sz;
    item_cnt++;

    const Result prc = write_pfs0(sd, "/kaihen/bin/game/next.nsp", items, item_cnt);
    free(npdm_buf);
    if (subsdk_owned) free(subsdk_buf);
    free(patched_sdk);
    if (R_FAILED(prc)) {
        nupClose(&nup);
        snprintf(out_msg, out_msg_sz, "write next.nsp failed: 0x%x", prc);
        return prc;
    }

    // 3. Tell nupvfs.nso which game is armed + arm one-shot SetNextPackage in kaiHEN
    Service ro = {}, hen = {};
    Result rc = kaihenGetRoSession(&ro);
    if (R_SUCCEEDED(rc))
        rc = kaihenOpenHomebrewSession(&ro, &hen);
    if (R_SUCCEEDED(rc)) {
        HenPluginName pname = {};
        snprintf(pname.name, sizeof(pname.name), "%s", NUPVFS_PLUGIN_NAME);
        Service vfs = {};
        if (R_SUCCEEDED(henOpenPlugin(&hen, &pname, &vfs))) {
            const NupVfsActiveGame ag = {
                .title_id = nup.title_id ? nup.title_id : entry->title_id,
                .prog_idx = nup.raw_is_subprogram ? 1u : 0u,
                .flags = NUPVFS_FLAG_MODS,
            };
            serviceDispatchIn(&vfs, NupVfsCmd_SetActiveGame, ag,
                .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
                .buffers = {{ nup.raw_root, strlen(nup.raw_root) + 1 }});
            serviceClose(&vfs);
        }

        NupHenNextPackage pkg = {};
        pkg.auto_arm = 1;
        snprintf(pkg.path, sizeof(pkg.path), "@Sdcard:/kaihen/bin/game/next.nsp");
        rc = serviceDispatchIn(&hen, HEN_CMD_SET_NEXT_PACKAGE, pkg);
        serviceClose(&hen);
    }
    nupClose(&nup);

    if (R_SUCCEEDED(rc)) {
        snprintf(out_msg, out_msg_sz, "Native Loader armed! Return to HOME & tap donor title.");
    } else {
        snprintf(out_msg, out_msg_sz, "next.nsp built; HEN SetNextPackage rc=0x%x", rc);
    }
    return rc;
}
