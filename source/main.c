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
    nupSvcHipcSetVfsPlugin(vfs_h, vfs_active ? vfs_info.flags : (NUPVFS_FLAG_MODS | NUPVFS_FLAG_CACHE));

    if (vfs_active && (vfs_info.flags & NUPVFS_FLAG_NATIVE)) {
        char msg[0x100] = {};
        if (R_SUCCEEDED(nupArmNativeLoaderBoot(&g_sd, entry, msg, sizeof(msg)))) {
            if (vfs_h != INVALID_HANDLE) svcCloseHandle(vfs_h);
            if (hen_sm != INVALID_HANDLE) svcCloseHandle(hen_sm);
            return 0;
        }
    }

    nupDiagReset();
    nupTraceReset(trace_mode);

    char log_path[0x80];
    if (trace_mode)
        snprintf(log_path, sizeof(log_path), "/kaihen/traces/%016llx.log", (unsigned long long)entry->title_id);
    else
        snprintf(log_path, sizeof(log_path), "/kaihen/nup-loader.log");

    nupLogInit(&g_sd, log_path);
    nupLogf("=== nup-loader [build=" NUP_BUILD_TAG "] (%s%s): %s (tid=%016llx) ===\n",
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
        nupLogf("[5/6] tearing down console/fsdev/hid/applet\n");
        svcSleepThread(300000000ULL);
        consoleExit(NULL);
        fsdevUnmountDevice("sdmc");
        hidExit();
    } else {
        nupLogf("[5/6] headless handoff (console/vi/nv/hid never initialized), closing applet\n");
    }

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
    // Self-test patched SVC #0x29 thunk in sdk BEFORE clearing TLS or calling nn::init::Start
    {
        const u32 svc29_off = elfGetSdkSvc29Off();
        const LoadedModule* sdk_mod = NULL;
        for (u32 i = 0; i < g_mods.count; i++) {
            if (strcmp(g_mods.mods[i].name, "sdk") == 0) { sdk_mod = &g_mods.mods[i]; break; }
        }
        if (sdk_mod) {
            MemoryInfo mi0 = {}, mi1 = {}, mi2 = {};
            u32 pi = 0;
            svcQueryMemory(&mi0, &pi, sdk_mod->nro_base);
            svcQueryMemory(&mi1, &pi, sdk_mod->nso_base);
            extern void nup_svc_entry(void);
            svcQueryMemory(&mi2, &pi, (u64)(uintptr_t)nup_svc_entry);
            nupLogf("[self-test] sdk.nro=%016llx(t=%u p=%u sz=0x%llx) sdk.nso=%016llx(t=%u p=%u) entry=%016llx(t=%u p=%u)\n",
                    (unsigned long long)sdk_mod->nro_base, mi0.type, mi0.perm, (unsigned long long)mi0.size,
                    (unsigned long long)sdk_mod->nso_base, mi1.type, mi1.perm,
                    (unsigned long long)(uintptr_t)nup_svc_entry, mi2.type, mi2.perm);
            if (svc29_off >= 8 && (mi1.perm & Perm_R)) {
                const u32* w = (const u32*)(uintptr_t)(sdk_mod->nso_base + svc29_off - 8);
                nupLogf("[self-test] sdk+0x%x words: %08x %08x %08x %08x %08x %08x\n",
                        svc29_off - 8, w[0], w[1], w[2], w[3], w[4], w[5]);
                const u64 fn_addr = (w[0] == 0xD503245Fu && w[1] == 0xF81F0FE0u)
                    ? (sdk_mod->nso_base + svc29_off - 8)
                    : (w[1] == 0xF81F0FE0u ? (sdk_mod->nso_base + svc29_off - 4) : 0);
                if (fn_addr) {
                    nupLogf("[self-test] invoking patched sdk svcGetInfo @ %016llx...\n",
                            (unsigned long long)fn_addr);
                    typedef Result (*SdkGetInfoFn)(u64*, u32, Handle, u64);
                    u64 out_val = 0;
                    const Result trc = ((SdkGetInfoFn)(uintptr_t)fn_addr)(
                        &out_val, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
                    nupLogf("[self-test] patched sdk svcGetInfo OK! rc=0x%x val=0x%llx\n",
                            trc, (unsigned long long)out_val);
                }
            }
            if (init_start_addr && (mi1.perm & Perm_R)) {
                const u32* iw = (const u32*)(uintptr_t)init_start_addr;
                nupLogf("[self-test] nn::init::Start @ %016llx words: %08x %08x %08x %08x\n",
                        (unsigned long long)init_start_addr, iw[0], iw[1], iw[2], iw[3]);
            }
        }
    }
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
    if (g_sd_open &&
        (nupUiProbeArgv(&g_sd, argc, argv, &auto_entry, &auto_trace) ||
         nupUiReadAutolaunch(&g_sd, &auto_entry, &auto_trace))) {
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
            nupArmNativeLoaderBoot(&g_sd, &g_entries[g_cursor], status, sizeof(status));
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
