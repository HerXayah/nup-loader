// SPDX-License-Identifier: MIT
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <switch.h>
#include <kaihen.h>

#include "caps.h"
#include "diag.h"
#include "elf_loader.h"
#include "hooks.h"
#include "log.h"
#include "native_boot.h"
#include "nup.h"
#include "nupvfs_proto.h"
#include "svc_hipc.h"
#include "trace.h"
#include "ui.h"
#include "vfs_romfs.h"

#define NUP_BUILD_TAG "0325-cap55"

static bool g_romfs_ui_printed = false;

static void romfs_progress_ui(u32 dirs, u32 files) {
    printf("\r  [4/6] Indexing RomFS: %u dirs, %u files...   ", dirs, files);
    consoleUpdate(NULL);
    g_romfs_ui_printed = true;
}

// Keep libnx's own heap compact (256 MiB: enough for NSO staging)
// so ~5.8 GiB remains free for the launched game's heap and GPU/virtual memory.
size_t __nx_heap_size = 0x10000000;

static NupEntry g_entries[MAX_NUP_ENTRIES];
static int g_entry_count = 0;
static int g_cursor = 0;
static char g_skip_note[256] = {};
static FsFileSystem g_sd = {};
static bool g_sd_open = false;
static NupArchive g_nup = {};
ModuleSet g_mods = {};
static bool g_from_once_autolaunch = false;

static u64 read_donor_cfg(FsFileSystem* sd, bool want_sw1) {
    if (!sd) return 0;
    FsFile f = {};
    if (R_FAILED(nupRawFsOpenFile(sd, "/kaihen/donors.cfg", FsOpenMode_Read, &f)))
        return 0;
    char buf[512] = {};
    u64 got = 0;
    nupRawFileRead(&f, 0, buf, sizeof(buf) - 1, &got);
    serviceClose(&f.s);
    if (!got) return 0;

    const char* key = want_sw1 ? "sw1=" : "sw2=";
    char* line = buf;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        while (*line == ' ' || *line == '\t' || *line == '\r') line++;
        if (strncmp(line, key, 4) == 0) {
            const u64 tid = strtoull(line + 4, NULL, 16);
            if (want_sw1 ? ((tid >> 56) == 0x01u) : ((tid >> 56) == 0x04u || (tid >> 56) == 0x01u))
                return tid;
        }
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

static bool ncm_db_key_has_sw2_program(NcmContentMetaDatabase* db, const NcmContentMetaKey* key) {
    u8 plat = 0;
    if (R_SUCCEEDED(ncmContentMetaDatabaseGetPlatform(db, &plat, key)) && plat != 0)
        return true;
    NcmContentInfo infos[16] = {};
    s32 written = 0;
    if (R_SUCCEEDED(ncmContentMetaDatabaseListContentInfo(db, &written, infos, 16, key, 0))) {
        for (s32 i = 0; i < written; i++) {
            if (infos[i].content_type == NcmContentType_Program && infos[i].id_offset > 0)
                return true;
        }
    }
    return false;
}

static bool ncm_title_has_sw2_upgrade(u64 app_id, NcmContentMetaDatabase* dbs, const bool* db_ok, int db_cnt) {
    const u64 patch_id = app_id | 0x800ULL;
    for (int d = 0; d < db_cnt; d++) {
        if (!db_ok[d]) continue;
        NcmContentMetaKey pkey = {};
        if (R_SUCCEEDED(ncmContentMetaDatabaseGetLatestContentMetaKey(&dbs[d], &pkey, patch_id))) {
            if (ncm_db_key_has_sw2_program(&dbs[d], &pkey))
                return true;
        }
    }
    return false;
}

static u32 read_pfs0_npdm_sysres(FsFileSystem* sd, const char* path) {
    if (!sd || !path) return 0;
    FsFile f = {};
    if (R_FAILED(nupRawFsOpenFile(sd, path, FsOpenMode_Read, &f)))
        return 0;
    u32 sysres = 0;
    u8 hdr[0x10] = {};
    u64 got = 0;
    if (R_SUCCEEDED(fsFileRead(&f, 0, hdr, sizeof(hdr), FsReadOption_None, &got)) &&
        got == sizeof(hdr) && memcmp(hdr, "PFS0", 4) == 0) {
        u32 count = 0, str_sz = 0;
        memcpy(&count, hdr + 4, 4);
        memcpy(&str_sz, hdr + 8, 4);
        if (count >= 1 && count <= 32 && str_sz > 0 && str_sz <= 0x400) {
            const u64 data_base = 0x10ULL + (u64)count * 24ULL + str_sz;
            u8 meta[0x20] = {};
            for (u32 i = 0; i < count; i++) {
                u8 ent[24] = {};
                if (R_FAILED(fsFileRead(&f, 0x10 + (s64)i * 24, ent, 24, FsReadOption_None, &got)) || got != 24)
                    break;
                u64 foff = 0, fsz = 0;
                u32 noff = 0;
                memcpy(&foff, ent + 0, 8);
                memcpy(&fsz, ent + 8, 8);
                memcpy(&noff, ent + 16, 4);
                if (noff >= str_sz || fsz < 0x20) continue;
                char name[32] = {};
                u64 nlen = str_sz - noff;
                if (nlen > sizeof(name) - 1) nlen = sizeof(name) - 1;
                if (R_SUCCEEDED(fsFileRead(&f, (s64)(0x10ULL + (u64)count * 24ULL + noff), name, nlen, FsReadOption_None, &got)) &&
                    strcmp(name, "main.npdm") == 0) {
                    if (R_SUCCEEDED(fsFileRead(&f, (s64)(data_base + foff), meta, sizeof(meta), FsReadOption_None, &got)) &&
                        got == sizeof(meta) && memcmp(meta, "META", 4) == 0) {
                        memcpy(&sysres, meta + 0x14, 4);
                    }
                    break;
                }
            }
        }
    }
    fsFileClose(&f);
    return sysres;
}

static u32 read_target_sysres(FsFileSystem* sd, const NupEntry* entry) {
    if (!sd || !entry || !entry->path[0]) return 0;
    static const char* const suffixes[2] = { "/game/exefs/main.npdm", "/exefs/main.npdm" };
    for (int i = 0; i < 2; i++) {
        char p[0x320];
        snprintf(p, sizeof(p), "%s%s", entry->path, suffixes[i]);
        FsFile f = {};
        if (R_SUCCEEDED(nupRawFsOpenFile(sd, p, FsOpenMode_Read, &f))) {
            u8 meta[0x20] = {};
            u64 got = 0;
            u32 sysres = 0;
            if (R_SUCCEEDED(fsFileRead(&f, 0, meta, sizeof(meta), FsReadOption_None, &got)) &&
                got == sizeof(meta) && memcmp(meta, "META", 4) == 0) {
                memcpy(&sysres, meta + 0x14, 4);
            }
            fsFileClose(&f);
            return sysres;
        }
    }
    return 0;
}

static u32 query_title_sysres(FsFileSystem* sd, Handle ldr_root, u64 tid, u8 storage_id, u8 attr) {
    char pol[0x80];
    snprintf(pol, sizeof(pol), "/kaihen/bin/policy/%016llx.nsp", (unsigned long long)tid);
    const u32 cached = read_pfs0_npdm_sysres(sd, pol);
    if (cached > 0)
        return cached;
    if (ldr_root == INVALID_HANDLE)
        return 0;

    Service loader = {};
    serviceCreate(&loader, ldr_root);
    loader.own_handle = 0;
    const struct {
        u8 attributes;
        u8 storage_id;
        u64 program_id;
    } req = { attr, storage_id, tid };
    u8 code_info[0x1a4] = {};
    FsFileSystem code_fs = {};
    u32 sysres = 0;
    if (R_SUCCEEDED(serviceDispatchIn(&loader, 0, req,
            .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
            .buffers = {{code_info, sizeof(code_info)}},
            .out_num_objects = 1,
            .out_objects = &code_fs.s))) {
        FsFile npdm = {};
        if (R_SUCCEEDED(fsFsOpenFile(&code_fs, "/main.npdm", FsOpenMode_Read, &npdm))) {
            u8 meta[0x20] = {};
            u64 got = 0;
            if (R_SUCCEEDED(fsFileRead(&npdm, 0, meta, sizeof(meta), FsReadOption_None, &got)) &&
                got == sizeof(meta) && memcmp(meta, "META", 4) == 0) {
                memcpy(&sysres, meta + 0x14, 4);
            }
            fsFileClose(&npdm);
        }
        fsFsClose(&code_fs);
    }
    return sysres;
}

static u64 find_matching_donor(FsFileSystem* sd, Handle hen_sm, bool want_sw1, u32 min_sysres) {
    const u64 cfg_tid = read_donor_cfg(sd, want_sw1);
    if (cfg_tid)
        return cfg_tid;

    Result nrc = ncmInitialize();
    if (R_FAILED(nrc) && hen_sm != INVALID_HANDLE) {
        Handle ncm_h = INVALID_HANDLE;
        const SmServiceName encoded = smEncodeName("ncm");
        Service proxy = {};
        serviceCreate(&proxy, hen_sm);
        proxy.own_handle = 0;
        if (R_SUCCEEDED(serviceDispatchIn(&proxy, 1, encoded,
                .out_handle_attrs = {SfOutHandleAttr_HipcMove},
                .out_handles = &ncm_h)) && ncm_h != INVALID_HANDLE) {
            smAddOverrideHandle(encoded, ncm_h);
            nrc = ncmInitialize();
        }
    }
    if (R_FAILED(nrc))
        return 0;

    Handle ldr_root = INVALID_HANDLE;
    {
        Service ro = {}, hen = {};
        if (R_SUCCEEDED(kaihenGetRoSession(&ro))) {
            if (R_SUCCEEDED(kaihenOpenHomebrewSession(&ro, &hen))) {
                henGetLoaderRoot(&hen, &ldr_root);
                serviceClose(&hen);
            }
            serviceClose(&ro);
        }
    }

    static const NcmStorageId storages[3] = {
        NcmStorageId_SdCard,
        NcmStorageId_BuiltInUser,
        NcmStorageId_GameCard,
    };
    NcmContentMetaDatabase dbs[3] = {};
    bool db_ok[3] = {};
    for (int s = 0; s < 3; s++)
        db_ok[s] = R_SUCCEEDED(ncmOpenContentMetaDatabase(&dbs[s], storages[s]));

    u64 chosen = 0;
    u32 best_sysres = 0;
    bool best_has_s1_nsp = false;
    u64 fallback = 0;
    NcmContentMetaKey keys[64];

    if (want_sw1) {
        for (int s = 0; s < 3; s++) {
            if (!db_ok[s]) continue;
            s32 total = 0, written = 0;
            if (R_FAILED(ncmContentMetaDatabaseList(&dbs[s], &total, &written, keys, 64,
                    NcmContentMetaType_Application, 0,
                    0x0100000000010000ULL, 0x01FFFFFFFFFFFFFFULL,
                    NcmContentInstallType_Full)))
                continue;
            for (s32 i = 0; i < written; i++) {
                // Skip Switch 2 Edition titles (launching them boots 0400... program1)
                if (ncm_db_key_has_sw2_program(&dbs[s], &keys[i]) ||
                    ncm_title_has_sw2_upgrade(keys[i].id, dbs, db_ok, 3))
                    continue;
                if (!fallback)
                    fallback = keys[i].id;
                char s1_nsp[0x80];
                snprintf(s1_nsp, sizeof(s1_nsp), "/kaihen/bin/s1/%016llx.nsp",
                         (unsigned long long)keys[i].id);
                u32 et = 0;
                const bool has_nsp = (sd && R_SUCCEEDED(nupRawFsGetEntryType(sd, s1_nsp, &et)) &&
                                      et == FsDirEntryType_File);
                const u32 sr = query_title_sysres(sd, ldr_root, keys[i].id, (u8)storages[s], 0);
                const bool meets = (min_sysres > 0) ? (sr >= min_sysres) : (sr > 0);
                const bool best_meets = (min_sysres > 0) ? (best_sysres >= min_sysres) : (best_sysres > 0);
                bool better = false;
                if (!chosen) {
                    if (sr > 0 || has_nsp) better = true;
                } else if (meets && !best_meets) {
                    better = true;
                } else if (meets == best_meets) {
                    if (sr > best_sysres) better = true;
                    else if (sr == best_sysres && has_nsp && !best_has_s1_nsp) better = true;
                }
                if (better) {
                    chosen = keys[i].id;
                    best_sysres = sr;
                    best_has_s1_nsp = has_nsp;
                }
            }
        }
    } else {
        // Prefer native Switch 2 (0400...) titles with highest sysres
        for (int s = 0; s < 3; s++) {
            if (!db_ok[s]) continue;
            s32 total = 0, written = 0;
            if (R_FAILED(ncmContentMetaDatabaseList(&dbs[s], &total, &written, keys, 64,
                    NcmContentMetaType_Application, 0,
                    0x0400000000010000ULL, 0x04FFFFFFFFFFFFFFULL,
                    NcmContentInstallType_Full)))
                continue;
            for (s32 i = 0; i < written; i++) {
                const u32 sr = query_title_sysres(sd, ldr_root, keys[i].id, (u8)storages[s], 1);
                if (!chosen || sr > best_sysres) {
                    chosen = keys[i].id;
                    best_sysres = sr;
                }
            }
        }
        // Fallback: Switch 2 Edition (0100... with program1 upgrade)
        for (int s = 0; s < 3 && !chosen && !fallback; s++) {
            if (!db_ok[s]) continue;
            s32 total = 0, written = 0;
            if (R_FAILED(ncmContentMetaDatabaseList(&dbs[s], &total, &written, keys, 64,
                    NcmContentMetaType_Application, 0,
                    0x0100000000010000ULL, 0x01FFFFFFFFFFFFFFULL,
                    NcmContentInstallType_Full)))
                continue;
            for (s32 i = 0; i < written; i++) {
                if (ncm_db_key_has_sw2_program(&dbs[s], &keys[i]) ||
                    ncm_title_has_sw2_upgrade(keys[i].id, dbs, db_ok, 3)) {
                    fallback = keys[i].id;
                    break;
                }
            }
        }
    }

    if (ldr_root != INVALID_HANDLE)
        svcCloseHandle(ldr_root);
    for (int s = 0; s < 3; s++) {
        if (db_ok[s]) ncmContentMetaDatabaseClose(&dbs[s]);
    }
    ncmExit();
    return chosen ? chosen : fallback;
}

static Result try_auto_donor_pivot(FsFileSystem* sd, Handle hen_sm,
                                   const NupEntry* entry, bool trace_mode,
                                   bool want_sw1, bool native_boot,
                                   bool headless, char* out_msg, size_t out_msg_sz) {
    u64 host_tid = 0;
    svcGetInfo(&host_tid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
    const u32 target_sysres = read_target_sysres(sd, entry);
    const bool host_matches = want_sw1 ? ((host_tid >> 56) == 0x01u) : ((host_tid >> 56) == 0x04u);
    const u64 donor = (native_boot && host_matches)
        ? host_tid
        : find_matching_donor(sd, hen_sm, want_sw1, target_sysres);
    if (!donor) {
        if (out_msg && out_msg_sz)
            snprintf(out_msg, out_msg_sz, "No installed %s donor found (set /kaihen/donors.cfg)",
                     want_sw1 ? "Switch 1" : "Switch 2");
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }

    if (!native_boot) {
        Result wrc = nupUiWriteAutolaunchOnce(sd, entry->path, trace_mode);
        if (R_FAILED(wrc)) {
            if (out_msg && out_msg_sz)
                snprintf(out_msg, out_msg_sz, "write autolaunch failed: 0x%x", wrc);
            return wrc;
        }
        Service ro = {}, hen = {};
        if (R_SUCCEEDED(kaihenGetRoSession(&ro)) &&
            R_SUCCEEDED(kaihenOpenHomebrewSession(&ro, &hen))) {
            serviceDispatch(&hen, HEN_CMD_CLEAR_NEXT_PACKAGE);
            serviceDispatch(&hen, HEN_CMD_ARM_NEXT_LAUNCH);
            serviceClose(&hen);
        }
    }

    if (!headless) {
        consoleClear();
        printf("  Auto-Donor Pivot (%s)\n", want_sw1 ? "Switch 1" : "Switch 2");
        printf("  Target: %s (%016llx)\n", entry->label, (unsigned long long)entry->title_id);
        printf("  Donor:  %016llx\n\n", (unsigned long long)donor);
        printf("  Switching donor automatically...\n");
        consoleUpdate(NULL);
    }

    Result lrc = appletRequestLaunchApplication(donor, NULL);
    nupLogf("[pivot] want_sw1=%d native=%d donor=%016llx appletRequestLaunchApplication rc=0x%x\n",
            want_sw1 ? 1 : 0, native_boot ? 1 : 0, (unsigned long long)donor, lrc);
    if (R_SUCCEEDED(lrc)) {
        svcSleepThread(300000000ULL);
        return 0;
    }

    // Never leave a stale autolaunch.txt behind on failure (would hijack next HBMenu launch)
    if (!native_boot) {
        nupRawFsDeleteFile(sd, "/kaihen/autolaunch.txt");
    }
    if (out_msg && out_msg_sz)
        snprintf(out_msg, out_msg_sz, "%s donor %016llx auto-launch failed (0x%x); open a %s donor from HOME",
                 want_sw1 ? "Sw1" : "Sw2", (unsigned long long)donor, lrc,
                 want_sw1 ? "Switch 1" : "Switch 2");
    return lrc;
}

static void cb_notify_exception_ready(void) {
    nupLogf("[6/6] nn::init::Start -> notifyExceptionHandlerReady\n");
    nupDiagRegisterExceptionHandler(false);
}

static void cb_call_initializers(void) {
    nupLogf("[6/6] nn::init::Start -> callInitializers\n");
    elfRunInitArrays(&g_mods, nupDiagRegisterAbortObservers);
    nupOnBeforeNnMain();
    nupLogf("[6/6] callInitializers done -> entering nnMain\n");
}

static void cb_call_finalizers(void) {
    nupLogf("[6/6] nn::init::Start -> callFinalizers\n");
}

static void log_host_process_info(void) {
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

static void shrink_libnx_heap_for_game(void) {
    u64 heap_base = 0, heap_region_sz = 0, tot_before = 0, used_before = 0;
    svcGetInfo(&heap_base, InfoType_HeapRegionAddress, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&heap_region_sz, InfoType_HeapRegionSize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&tot_before, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&used_before, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);

    u64 high = heap_base;
    const u64 romfs_hi = nupSvcHipcMaxHeapAddr();
    if (romfs_hi > high) high = romfs_hi;
    for (u32 i = 0; i < g_mods.count; i++) {
        if (g_mods.mods[i].src_buf) {
            const u64 sz = g_mods.mods[i].src_size ? g_mods.mods[i].src_size : g_mods.mods[i].total_size;
            const u64 e = (u64)(uintptr_t)g_mods.mods[i].src_buf + sz;
            if (e > high) high = e;
        }
        if (g_mods.mods[i].bss_buf) {
            const u64 sz = g_mods.mods[i].bss_size ? g_mods.mods[i].bss_size : g_mods.mods[i].total_size;
            const u64 e = (u64)(uintptr_t)g_mods.mods[i].bss_buf + sz;
            if (e > high) high = e;
        }
    }
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
    if (high > heap_base)
        keep = ((high - heap_base) + 0x400000ull + 0x1fffffull) & ~0x1fffffull;
    void* shrunk_base = NULL;
    const Result shrink_rc = svcSetHeapSize(&shrunk_base, (size_t)keep);
    if (R_SUCCEEDED(shrink_rc))
        nupSvcHipcSetHostHeap((u64)(uintptr_t)shrunk_base, keep);
    u64 used_after = 0;
    svcGetInfo(&used_after, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    nupLogf("[5/6] heap shrink: heap_base=0x%llx high=0x%llx keep=0x%llx rc=0x%x used: 0x%llx -> 0x%llx (total=0x%llx)\n",
            (unsigned long long)heap_base, (unsigned long long)high,
            (unsigned long long)keep, shrink_rc,
            (unsigned long long)used_before, (unsigned long long)used_after,
            (unsigned long long)tot_before);
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
    nupLogf("=== nup-loader [build=" NUP_BUILD_TAG "] STATIC AUDIT: %s (tid=%016llx, RAW) ===\n",
            entry->path, (unsigned long long)entry->title_id);

    NupFileInfo exefs[NUP_MAX_EXEFS_FILES];
    u32 exefs_count = 0;
    if (!nupProbeRaw(&g_sd, entry->path, NULL, exefs, &exefs_count)) {
        nupLogf("[!] nupProbeRaw failed\n");
        nupLogClose();
        snprintf(out_status, out_status_sz, "audit failed: probe raw");
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    Result rc = nupOpenRaw(&g_nup, &g_sd, entry->path);
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
    nupCollectRuntimeCaps(&caps, &g_nup, exefs, exefs_count, &audit_mods, sel_tid);
    nupLogRuntimeCaps(&caps);

    printf("  Auditing %u modules...\n", audit_mods.count);
    consoleUpdate(NULL);

    ElfAuditSummary sum = {};
    elfRunStaticAudit(&audit_mods, &caps, hooksResolve, &sum);

    elfUnloadAuditModules(&audit_mods);
    nupClose(&g_nup);
    nupLogClose();

    snprintf(out_status, out_status_sz,
             "Audit -> %s (m=%u %s unres=%u tr=%u/%u stk=%s vam=%s)",
             audit_path, sum.module_count, sum.entry_kind,
             sum.unresolved_count, sum.trace_need_tramp, NUP_TRACE_MAX_SLOTS,
             caps.platform_stack_match ? "OK" : "MISMATCH",
             caps.vam_capable ? "ON" : "OFF");
    return 0;
}

static Result launch_nup(const NupEntry* entry, bool headless, bool trace_mode) {
    Handle hen_sm = INVALID_HANDLE;
    Handle vfs_h = INVALID_HANDLE;
    NupVfsInfo vfs_info = {};
    bool vfs_active = false;
    {
        Service ro = {}, hen = {};
        if (R_SUCCEEDED(kaihenGetRoSession(&ro)) &&
            R_SUCCEEDED(kaihenOpenHomebrewSession(&ro, &hen))) {
            henGetServiceManager(&hen, &hen_sm);
            HenPluginName pname = {};
            snprintf(pname.name, sizeof(pname.name), "%s", NUPVFS_PLUGIN_NAME);
            Service vfs = {};
            if (R_SUCCEEDED(henOpenPlugin(&hen, &pname, &vfs))) {
                if (R_SUCCEEDED(serviceDispatchOut(&vfs, NupVfsCmd_GetInfo, vfs_info)) &&
                    vfs_info.magic == NUPVFS_MAGIC) {
                    vfs_h = vfs.session;
                    vfs_active = true;
                    if (!trace_mode && (vfs_info.flags & NUPVFS_FLAG_TRACE))
                        trace_mode = true;
                } else {
                    serviceClose(&vfs);
                }
            }
            serviceClose(&hen);
        }
    }
    u32 eff_vfs_flags = vfs_active ? vfs_info.flags : (NUPVFS_FLAG_MODS | NUPVFS_FLAG_CACHE);
    bool hold_l_vanilla = false;
    {
        padConfigureInput(1, HidNpadStyleSet_NpadStandard);
        PadState launch_pad;
        padInitializeAny(&launch_pad);
        padUpdate(&launch_pad);
        if (padGetButtons(&launch_pad) & HidNpadButton_L) {
            hold_l_vanilla = true;
            eff_vfs_flags &= ~NUPVFS_FLAG_MODS;
        }
    }
    nupSvcHipcSetVfsPlugin(vfs_h, eff_vfs_flags);
    elfSetModContext(&g_sd, entry->title_id, (eff_vfs_flags & NUPVFS_FLAG_MODS) != 0);

    nupDiagReset();
    nupTraceReset(trace_mode);

    char log_path[0x80];
    if (trace_mode)
        snprintf(log_path, sizeof(log_path), "/kaihen/traces/%016llx.log", (unsigned long long)entry->title_id);
    else
        snprintf(log_path, sizeof(log_path), "/kaihen/nup-loader.log");

    nupLogInit(&g_sd, log_path);
    nupLogf("=== nup-loader [build=" NUP_BUILD_TAG "] (%s%s%s): %s (tid=%016llx) ===\n",
            headless ? "headless" : "ui",
            trace_mode ? "+TRACE" : "",
            hold_l_vanilla ? "+VANILLA(L)" : "",
            entry->path, (unsigned long long)entry->title_id);
    if (hold_l_vanilla)
        nupLogf("[mods] Hold-L detected: vanilla boot (all LayeredFS/ExeFS/IPS mods skipped)\n");

    if (vfs_active && (vfs_info.flags & NUPVFS_FLAG_NATIVE)) {
        char msg[0x100] = {};
        if (R_SUCCEEDED(nupArmNativeLoaderBoot(&g_sd, entry, msg, sizeof(msg)))) {
            const bool want_sw1 = ((entry->title_id >> 56) == 0x01u);
            try_auto_donor_pivot(&g_sd, hen_sm, entry, trace_mode, want_sw1, true, headless, msg, sizeof(msg));
            nupLogClose();
            if (vfs_h != INVALID_HANDLE) svcCloseHandle(vfs_h);
            if (hen_sm != INVALID_HANDLE) svcCloseHandle(hen_sm);
            return 0;
        }
    }

    // Auto-Donor Pivot when target stack (Switch 1 0100 vs Switch 2 0400) differs from host donor
    {
        u64 host_tid = 0;
        svcGetInfo(&host_tid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
        const bool target_is_sw1 = ((entry->title_id >> 56) == 0x01u);
        const bool target_is_sw2 = ((entry->title_id >> 56) == 0x04u);
        const bool host_is_sw1   = ((host_tid >> 56) == 0x01u);
        const bool host_is_sw2   = ((host_tid >> 56) == 0x04u);
        if ((target_is_sw1 && !host_is_sw1) || (target_is_sw2 && !host_is_sw2)) {
            nupLogf("[pivot] stack mismatch: host=%016llx target=%016llx once=%d\n",
                    (unsigned long long)host_tid, (unsigned long long)entry->title_id,
                    g_from_once_autolaunch ? 1 : 0);
            char pmsg[0x100] = {};
            Result prc = MAKERESULT(Module_Libnx, LibnxError_IncompatSysVer);
            if (!g_from_once_autolaunch) {
                prc = try_auto_donor_pivot(&g_sd, hen_sm, entry, trace_mode,
                                           target_is_sw1, false, headless,
                                           pmsg, sizeof(pmsg));
            } else {
                snprintf(pmsg, sizeof(pmsg), "Stack mismatch after pivot (host=%016llx vs target=%016llx)",
                         (unsigned long long)host_tid, (unsigned long long)entry->title_id);
            }
            if (R_SUCCEEDED(prc)) {
                nupLogClose();
                if (vfs_h != INVALID_HANDLE) svcCloseHandle(vfs_h);
                if (hen_sm != INVALID_HANDLE) svcCloseHandle(hen_sm);
                return 0;
            }
            // Never fall through and crash a Sw1 game inside a Sw2 process (or vice versa)
            nupLogf("[pivot] aborting mismatched launch: %s (rc=0x%x)\n", pmsg, prc);
            nupLogClose();
            if (vfs_h != INVALID_HANDLE) svcCloseHandle(vfs_h);
            if (hen_sm != INVALID_HANDLE) svcCloseHandle(hen_sm);
            if (!headless && pmsg[0]) {
                printf("\n  [pivot] %s\n", pmsg);
                consoleUpdate(NULL);
            }
            return prc;
        }
        // Same-stack sysres shortage (e.g. Sw1 donor with sysres=0 running VAM target like XCX):
        // auto-pivot once if a higher-sysres donor (or newly cached Mount #1 policy) is available.
        if (!g_from_once_autolaunch && (target_is_sw1 || target_is_sw2)) {
            u64 host_sysres = 0;
            svcGetInfo(&host_sysres, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
            const u32 target_sysres = read_target_sysres(&g_sd, entry);
            if (target_sysres > 0 && host_sysres < target_sysres) {
                char pol[0x80];
                snprintf(pol, sizeof(pol), "/kaihen/bin/policy/%016llx.nsp", (unsigned long long)host_tid);
                const u32 host_cached_sr = read_pfs0_npdm_sysres(&g_sd, pol);
                const u64 better = find_matching_donor(&g_sd, hen_sm, target_is_sw1, target_sysres);
                if ((better && better != host_tid) || host_cached_sr >= target_sysres) {
                    nupLogf("[pivot] sysres upgrade: host=%016llx (0x%llx, cached=0x%x) target=0x%x -> donor=%016llx\n",
                            (unsigned long long)host_tid, (unsigned long long)host_sysres,
                            host_cached_sr, target_sysres,
                            (unsigned long long)(better ? better : host_tid));
                    char pmsg[0x100] = {};
                    const Result prc = try_auto_donor_pivot(&g_sd, hen_sm, entry, trace_mode,
                                                            target_is_sw1, false, headless,
                                                            pmsg, sizeof(pmsg));
                    if (R_SUCCEEDED(prc)) {
                        nupLogClose();
                        if (vfs_h != INVALID_HANDLE) svcCloseHandle(vfs_h);
                        if (hen_sm != INVALID_HANDLE) svcCloseHandle(hen_sm);
                        return 0;
                    }
                    nupLogf("[pivot] sysres upgrade failed (continuing on current donor): %s (rc=0x%x)\n",
                            pmsg, prc);
                }
            }
        }
    }

    if (!headless) {
        consoleClear();
        printf("  %s %s\n", trace_mode ? "TRACE Launching" : "Launching", entry->label);
        printf("  Title ID: %016llx\n", (unsigned long long)entry->title_id);
        printf("  Log: %s\n\n", log_path);
        consoleUpdate(NULL);
    }

    nupLogf("[1/6] hen_sm=%s nupvfs=%s (slots=%u flags=0x%x cbtn=%u rc=0x%x)\n",
            hen_sm != INVALID_HANDLE ? "ready" : "unavailable",
            vfs_active ? "ACTIVE" : "fallback-local",
            vfs_info.slot_count, vfs_info.flags, vfs_info.cbutton_events, vfs_info.cbutton_rc);
    nupDiagDumpLatestErpt(hen_sm, &g_sd);
    if (!headless) {
        printf("  [1/6] HEN SM proxy: %s | nupvfs: %s\n",
               hen_sm != INVALID_HANDLE ? "ready" : "unavailable",
               vfs_active ? "resident plugin" : "local fallback");
        consoleUpdate(NULL);
    }

    Result rc = ldrRoInitialize();
    if (R_FAILED(rc)) {
        nupLogf("[!] ldrRoInitialize failed: 0x%x\n", rc);
        return rc;
    }

    NupFileInfo exefs[NUP_MAX_EXEFS_FILES];
    u32 exefs_count = 0;
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
    nupLogf("[2/6] RAW opened: %s exefs=%u romfs=%d (%s) app_root=%s\n",
            entry->path, exefs_count, g_nup.has_romfs ? 1 : 0,
            g_nup.raw_romfs_root[0] ? g_nup.raw_romfs_root : "none",
            g_nup.raw_app_root);

    if (!headless) { printf("  [3/6] Mapping ExeFS NSOs via ldr:ro...\n"); consoleUpdate(NULL); }
    rc = elfLoadNupModules(&g_mods, &g_nup, exefs, exefs_count);
    if (R_FAILED(rc)) {
        nupLogf("[!] elfLoadNupModules failed: 0x%x\n", rc);
        nupLogFlush();
        nupClose(&g_nup);
        return rc;
    }
    nupLogf("[3/6] ExeFS mapped: %u modules\n", g_mods.count);
    nupLogFlush();

    const u64 sel_tid = g_nup.title_id ? g_nup.title_id : entry->title_id;
    elfAttachSwitch1Compat(&g_mods, sel_tid);
    NupRuntimeCapabilities caps = {};
    nupCollectRuntimeCaps(&caps, &g_nup, exefs, exefs_count, &g_mods, sel_tid);
    if (trace_mode) {
        if (!headless) { printf("  [4/6] Running capability + hook/capacity audit...\n"); consoleUpdate(NULL); }
        nupLogRuntimeCaps(&caps);
        elfRunStaticAudit(&g_mods, &caps, hooksResolve, NULL);
    }
    if (!headless) { printf("  [4/6] Indexing RomFS & preparing VFS...\n"); consoleUpdate(NULL); }
    nupLogf("[4/6] hooksInit start...\n");
    g_romfs_ui_printed = false;
    vfsRomfsSetProgressCallback(headless ? NULL : romfs_progress_ui);
    hooksInit(&g_nup, &g_sd, &caps, hen_sm);
    vfsRomfsSetProgressCallback(NULL);
    if (!headless && g_romfs_ui_printed) { printf("\n"); consoleUpdate(NULL); }
    if (!headless) { printf("  [4/6] Relocating %u modules...\n", g_mods.count); consoleUpdate(NULL); }
    nupLogf("[4/6] VFS/hooks ready, relocating %u modules...\n", g_mods.count);
    nupLogFlush();
    u32 unresolved = 0;
    rc = elfRelocateAll(&g_mods, hooksResolve, &unresolved);
    if (R_FAILED(rc)) {
        nupLogf("[!] elfRelocateAll failed: 0x%x\n", rc);
        nupLogFlush();
        return rc;
    }

    u64 init_start_addr = elfFindSymbol(&g_mods, "_ZN2nn4init5StartEmmPFvvES2_S2_");
    bool init_start_4arg = false;
    if (!init_start_addr) {
        init_start_addr = elfFindSymbol(&g_mods, "_ZN2nn4init5StartEmmPFvvES2_");
        if (init_start_addr) init_start_4arg = true;
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
        nupLogf("[5/6] tearing down console/win/fsdev/time/hid/applet\n");
        svcSleepThread(300000000ULL);
        consoleExit(NULL);
    } else {
        nupLogf("[5/6] headless handoff: tearing down __appInit win/fsdev/time/hid/applet\n");
    }
    extern void __nx_win_exit(void);
    __nx_win_exit();
    fsdevUnmountAll();
    timeExit();
    hidExit();

    if (caps.target_is_switch1 && !caps.has_compat2) {
        Result gsv_rc = gsvInitialize();
        Handle nv_h = INVALID_HANDLE;
        Result nv_rc = R_SUCCEEDED(gsv_rc) ? gsvOpenNvServices(&nv_h) : gsv_rc;
        nupLogf("[5/6] Switch1 GSV nvservices: gsv=0x%x nv=0x%x h=0x%x\n", gsv_rc, nv_rc, nv_h);
        if (R_SUCCEEDED(nv_rc) && nv_h != INVALID_HANDLE)
            hooksSetNvHandle(nv_h);
        if (R_SUCCEEDED(gsv_rc))
            appletExit();
    }
    appletExit();

    log_host_process_info();
    nupLogSetPersistentHandle(true);
    nupDiagStartHeartbeat();
    shrink_libnx_heap_for_game();

    // Clear libnx's ThreadVars from main thread TLS [0x120..0x200) before handing off
    // to the game's SDK (SDK 16+/19+/20+/22+ expect this area zeroed and use 0x1E0..0x1FF
    // for their own C-library/TLS pointers). Preserve [0x100..0x120) which holds kernel
    // state (pin count at 0x100, thread handle at 0x110).
    {
        u8* tls = (u8*)armGetTls();
        nupLogf("[5/6] main TLS kernel=[0x%llx, 0x%llx, 0x%llx, 0x%llx] clearing [0x120..0x200)\n",
                (unsigned long long)*(const u64*)(tls + 0x100),
                (unsigned long long)*(const u64*)(tls + 0x108),
                (unsigned long long)*(const u64*)(tls + 0x110),
                (unsigned long long)*(const u64*)(tls + 0x118));
        memset(tls + 0x120, 0, 0xE0);
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
        nupDiagRegisterExceptionHandler(false);
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
        nupDiagRegisterExceptionHandler(false);
        if (startup_addr) {
            nupLogf("[6/6] calling nninitStartup @ %016llx\n", (unsigned long long)startup_addr);
            ((void (*)(void))(uintptr_t)startup_addr)();
        }
        if ((fn = elfFindSymbolSkipCompat1(&g_mods, "__nnDetailInitLibc2")) ||
            (fn = elfFindSymbolSkipCompat1(&g_mods, "_init_libc2"))) {
            nupLogf("[6/6] calling InitLibc2 @ %016llx\n", (unsigned long long)fn);
            ((void (*)(void))(uintptr_t)fn)();
        }
        elfRunInitArrays(&g_mods, nupDiagRegisterAbortObservers);
        nupOnBeforeNnMain();
        nupLogf("[6/6] calling nnMain @ %016llx\n", (unsigned long long)main_addr);
        ((void (*)(void))(uintptr_t)main_addr)();
    }
    nupLogClose();
    return 0;
}

int main(int argc, char** argv) {
    if (R_SUCCEEDED(fsOpenSdCardFileSystem(&g_sd)))
        g_sd_open = true;

    NupEntry auto_entry = {};
    bool auto_trace = false;
    bool from_once = false;
    if (g_sd_open &&
        (nupUiProbeArgv(&g_sd, argc, argv, &auto_entry, &auto_trace) ||
         nupUiReadAutolaunch(&g_sd, &auto_entry, &auto_trace, &from_once))) {
        g_from_once_autolaunch = from_once;
        launch_nup(&auto_entry, true, auto_trace);
        fsFsClose(&g_sd);
        return 0;
    }

    consoleInit(NULL);
    fsdevMountSdmc();

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    char status[0x100] = {};
    if (g_sd_open) {
        nupUiScanAll(&g_sd, g_entries, &g_entry_count, g_skip_note, sizeof(g_skip_note));
        if (g_cursor >= g_entry_count) g_cursor = 0;
    } else {
        snprintf(status, sizeof(status), "failed to open SD filesystem");
    }
    nupUiDrawMenu(g_entries, g_entry_count, g_cursor, status, g_skip_note);

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
            nupUiDrawMenu(g_entries, g_entry_count, g_cursor, status, g_skip_note);
            continue;
        }

        if (down & HidNpadButton_X) {
            nupUiScanAll(&g_sd, g_entries, &g_entry_count, g_skip_note, sizeof(g_skip_note));
            if (g_cursor >= g_entry_count) g_cursor = 0;
            snprintf(status, sizeof(status), "rescanned (%d found)", g_entry_count);
            nupUiDrawMenu(g_entries, g_entry_count, g_cursor, status, g_skip_note);
            continue;
        }

        if ((down & HidNpadButton_L) && g_entry_count > 0) {
            audit_nup(&g_entries[g_cursor], status, sizeof(status));
            nupUiDrawMenu(g_entries, g_entry_count, g_cursor, status, g_skip_note);
            continue;
        }

        if ((down & HidNpadButton_R) && g_entry_count > 0) {
            snprintf(status, sizeof(status), "Packing /kaihen/bin/game/next.nsp for Native Loader Boot...");
            nupUiDrawMenu(g_entries, g_entry_count, g_cursor, status, g_skip_note);
            if (R_SUCCEEDED(nupArmNativeLoaderBoot(&g_sd, &g_entries[g_cursor], status, sizeof(status)))) {
                Handle hen_sm = INVALID_HANDLE;
                Service ro = {}, hen = {};
                if (R_SUCCEEDED(kaihenGetRoSession(&ro)) &&
                    R_SUCCEEDED(kaihenOpenHomebrewSession(&ro, &hen))) {
                    henGetServiceManager(&hen, &hen_sm);
                    serviceClose(&hen);
                }
                const bool want_sw1 = ((g_entries[g_cursor].title_id >> 56) == 0x01u);
                const Result prc = try_auto_donor_pivot(&g_sd, hen_sm, &g_entries[g_cursor],
                                                        false, want_sw1, true, false,
                                                        status, sizeof(status));
                if (hen_sm != INVALID_HANDLE) svcCloseHandle(hen_sm);
                if (R_SUCCEEDED(prc))
                    break;
            }
            nupUiDrawMenu(g_entries, g_entry_count, g_cursor, status, g_skip_note);
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
                nupUiDrawMenu(g_entries, g_entry_count, g_cursor, status, g_skip_note);
            }
        }
    }

    if (g_sd_open)
        fsFsClose(&g_sd);
    fsdevUnmountDevice("sdmc");
    consoleExit(NULL);
    return 0;
}
