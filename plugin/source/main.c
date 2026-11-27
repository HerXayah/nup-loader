// SPDX-License-Identifier: MIT
// Resident kaiHEN VFS + GameChat C-Button HBMenu plugin (/kaihen/plugins/nupvfs.nso)
//
// Runs as a separate background Horizon process started by kaiHEN bootstrap:
// - Owns all VfsRomfs header/hash/meta tables, LayeredFS overlays, and SD FsFile
//   LRU caches in its own 6 MiB heap (zero game RAM overhead; persists across launches).
// - Serves zero-copy HipcMapAlias A/B buffer IPC to nup-loader.nro and romfs-subsdk.nso.
// - Exposes live settings in ounce-hbmenu (Settings -> Plugins -> nupvfs) via
//   kaihen/plugin_settings.h.
// - Watches Switch 2 GameChat (C) button (hid:sys cmds 171/181) to arm HBMenu ONLY
//   (never a backup game) via HenHomebrewCommand_ClearNextPackage + ArmNextLaunch.

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <switch.h>
#include <kaihen.h>
#include <kaihen/plugin.h>
#include <kaihen/plugin_settings.h>

#include "nupvfs_proto.h"
#include "vfs_romfs.h"

// Plugin runtime configuration (linked with -lkaihen_plugin -lounce_core)
// Keep default __nx_fs_num_sessions (1) from libkaihen_plugin, matching ouncerpc.nso.
u32 __nx_applet_type = AppletType_None;
size_t __nx_heap_size = 0x800000; // 8 MiB private plugin heap (matches ouncerpc.nso)

void __appInit(void) {}
void __appExit(void) {}

#define MAX_CLIENT_SESSIONS 16
#define PLUGIN_THREAD_STACK 0x8000
#define PLUGIN_THREAD_PRIO  0x2c
#define CBUTTON_THREAD_PRIO 0x34
#define IPC_MSG_SIZE        0x100u

// --- Logging (SD-only, never NAND) ---

static FsFileSystem g_sd = {};
static bool g_sd_ready = false;
static Mutex g_log_lock;
static s64 g_log_off = 0;

static void plugin_log_line(const char* line) {
    if (!g_sd_ready || !line || !line[0])
        return;
    mutexLock(&g_log_lock);
    FsFile f = {};
    if (R_FAILED(fsFsOpenFile(&g_sd, "/kaihen/nupvfs.log", FsOpenMode_Write | FsOpenMode_Append, &f))) {
        fsFsCreateFile(&g_sd, "/kaihen/nupvfs.log", 0, 0);
        if (R_FAILED(fsFsOpenFile(&g_sd, "/kaihen/nupvfs.log", FsOpenMode_Write | FsOpenMode_Append, &f))) {
            mutexUnlock(&g_log_lock);
            return;
        }
        g_log_off = 0;
    } else if (g_log_off == 0) {
        s64 sz = 0;
        if (R_SUCCEEDED(fsFileGetSize(&f, &sz)) && sz > 0)
            g_log_off = sz;
    }
    const size_t len = strlen(line);
    if (R_SUCCEEDED(fsFileWrite(&f, g_log_off, line, len, FsWriteOption_Flush)))
        g_log_off += (s64)len;
    fsFileClose(&f);
    fsFsCommit(&g_sd);
    mutexUnlock(&g_log_lock);
}

// Required by shared source/vfs_romfs.c (log.h)
void nupLogf(const char* fmt, ...) {
    char buf[0x200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    plugin_log_line(buf);
}

// --- Settings (exposed live in ounce-hbmenu Settings -> Plugins -> nupvfs) ---

static KaihenPluginSetting g_settings[] = {
    { "games",   "Show Games in HBMenu", KaihenPluginSetting_Bool, 1, 0, 1, 1, {0} },
    { "mods",    "LayeredFS Mods",       KaihenPluginSetting_Bool, 1, 0, 1, 1, {0} },
    { "trace",   "Trace Launch",         KaihenPluginSetting_Bool, 0, 0, 1, 1, {0} },
    { "cache",   "Keep RomFS Cache",     KaihenPluginSetting_Bool, 1, 0, 1, 1, {0} },
    { "native",  "Native Loader Boot",   KaihenPluginSetting_Bool, 0, 0, 1, 1, {0} },
    { "cbutton", "C Button -> HBMenu",   KaihenPluginSetting_Bool, 1, 0, 1, 1, {0} },
};

static u32 settings_flags(void) {
    u32 f = 0;
    if (g_settings[0].value) f |= NUPVFS_FLAG_HBMENU_GAMES;
    if (g_settings[1].value) f |= NUPVFS_FLAG_MODS;
    if (g_settings[2].value) f |= NUPVFS_FLAG_TRACE;
    if (g_settings[3].value) f |= NUPVFS_FLAG_CACHE;
    if (g_settings[4].value) f |= NUPVFS_FLAG_NATIVE;
    if (g_settings[5].value) f |= NUPVFS_FLAG_CBUTTON;
    return f;
}

static void settings_save(void) {
    if (!g_sd_ready)
        return;
    char buf[256];
    const int n = snprintf(buf, sizeof(buf),
        "games=%u\nmods=%u\ntrace=%u\ncache=%u\nnative=%u\ncbutton=%u\n",
        (unsigned)g_settings[0].value,
        (unsigned)g_settings[1].value,
        (unsigned)g_settings[2].value,
        (unsigned)g_settings[3].value,
        (unsigned)g_settings[4].value,
        (unsigned)g_settings[5].value);
    if (n <= 0)
        return;
    fsFsDeleteFile(&g_sd, "/kaihen/nupvfs.cfg");
    fsFsCreateFile(&g_sd, "/kaihen/nupvfs.cfg", n, 0);
    FsFile f = {};
    if (R_SUCCEEDED(fsFsOpenFile(&g_sd, "/kaihen/nupvfs.cfg", FsOpenMode_Write, &f))) {
        fsFileWrite(&f, 0, buf, (size_t)n, FsWriteOption_Flush);
        fsFileClose(&f);
        fsFsCommit(&g_sd);
    }
}

static void settings_load(void) {
    if (!g_sd_ready)
        return;
    FsFile f = {};
    if (R_FAILED(fsFsOpenFile(&g_sd, "/kaihen/nupvfs.cfg", FsOpenMode_Read, &f)))
        return;
    char buf[512] = {};
    u64 got = 0;
    fsFileRead(&f, 0, buf, sizeof(buf) - 1, FsReadOption_None, &got);
    fsFileClose(&f);
    if (!got)
        return;
    char* line = buf;
    while (*line) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char* eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            const u8 val = (u8)(atoi(eq + 1) ? 1 : 0);
            for (size_t i = 0; i < sizeof(g_settings) / sizeof(g_settings[0]); i++) {
                if (strcmp(line, g_settings[i].key) == 0)
                    g_settings[i].value = val;
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
}

// --- Cached VfsRomfs slot pool (owned in plugin heap, zero game RAM) ---

typedef struct {
    bool in_use;
    u64 last_use;
    u64 title_id;
    u32 prog_idx;
    char key[0x600]; // Concatenated base + overlay paths for cache hit matching
    VfsRomfs romfs;
} VfsSlot;

static Mutex g_vfs_lock;
static VfsSlot g_slots[NUPVFS_MAX_SLOTS] = {};
static u64 g_slot_clock = 0;

// Active game metadata for native Loader boot (romfs-subsdk queries this)
static NupVfsActiveGame g_active_game = {};
static char g_active_path[NUPVFS_PATH_MAX] = {};

static void clear_all_slots(void) {
    mutexLock(&g_vfs_lock);
    for (u32 i = 0; i < NUPVFS_MAX_SLOTS; i++) {
        if (g_slots[i].in_use) {
            vfsRomfsDestroy(&g_slots[i].romfs);
            memset(&g_slots[i], 0, sizeof(g_slots[i]));
        }
    }
    mutexUnlock(&g_vfs_lock);
    nupLogf("[nupvfs] cleared all cached RomFS slots\n");
}

static u32 count_used_slots(void) {
    u32 n = 0;
    mutexLock(&g_vfs_lock);
    for (u32 i = 0; i < NUPVFS_MAX_SLOTS; i++) {
        if (g_slots[i].in_use) n++;
    }
    mutexUnlock(&g_vfs_lock);
    return n;
}

static Result on_setting_apply(void* ctx, const KaihenPluginSetting* setting) {
    (void)ctx;
    if (!setting)
        return 0;
    settings_save();
    if (strcmp(setting->key, "cache") == 0 && setting->value == 0)
        clear_all_slots();
    nupLogf("[nupvfs] setting '%s' = %u\n", setting->key, (unsigned)setting->value);
    return 0;
}

static const KaihenPluginSettingsTable g_settings_table = {
    .name = "nupvfs (Game VFS & C-Button)",
    .settings = g_settings,
    .count = (u32)(sizeof(g_settings) / sizeof(g_settings[0])),
    .apply = on_setting_apply,
    .context = NULL,
};

// --- VFS Command Implementations ---

static Result cmd_mount_romfs(const NupVfsMountReq* req, const u8* layers_buf, size_t layers_sz,
                              NupVfsMountReply* out) {
    if (!g_sd_ready || !req || !layers_buf || !layers_sz || req->num_layers == 0 ||
        req->num_layers > NUPVFS_MAX_LAYERS)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    // Parse NUL-terminated paths from layers_buf: layer[0] = base, layer[1..] = overlays
    char paths[NUPVFS_MAX_LAYERS][NUPVFS_PATH_MAX];
    const char* ov_ptrs[NUPVFS_MAX_LAYERS];
    u32 parsed = 0;
    size_t pos = 0;
    while (pos < layers_sz && parsed < req->num_layers) {
        const size_t max_len = layers_sz - pos;
        const size_t slen = strnlen((const char*)(layers_buf + pos), max_len);
        if (slen == 0 || slen >= NUPVFS_PATH_MAX)
            break;
        memcpy(paths[parsed], layers_buf + pos, slen);
        paths[parsed][slen] = '\0';
        parsed++;
        pos += slen + 1;
    }
    if (parsed == 0)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    // Respect live LayeredFS Mods toggle: strip overlays beyond base if mods disabled
    const u32 active_layers = g_settings[1].value ? parsed : 1u;
    int ov_cnt = 0;
    for (u32 i = 1; i < active_layers; i++)
        ov_ptrs[ov_cnt++] = paths[i];

    // Build canonical cache key
    char key[0x600] = {};
    size_t klen = 0;
    for (u32 i = 0; i < active_layers && klen + 2 < sizeof(key); i++) {
        const int w = snprintf(key + klen, sizeof(key) - klen, "%s%s", i ? "|" : "", paths[i]);
        if (w <= 0) break;
        klen += (size_t)w < sizeof(key) - klen ? (size_t)w : sizeof(key) - klen - 1;
    }

    mutexLock(&g_vfs_lock);
    const bool keep_cache = (g_settings[3].value != 0);

    // 1. Check cache hit
    if (keep_cache) {
        for (u32 i = 0; i < NUPVFS_MAX_SLOTS; i++) {
            if (g_slots[i].in_use && strcmp(g_slots[i].key, key) == 0) {
                g_slots[i].last_use = ++g_slot_clock;
                out->slot_id = i + 1u;
                out->cached = 1u;
                out->total_size = vfsRomfsSize(&g_slots[i].romfs);
                mutexUnlock(&g_vfs_lock);
                nupLogf("[nupvfs] MountRomfs CACHE HIT slot=%u key='%s' size=0x%llx\n",
                        out->slot_id, key, (unsigned long long)out->total_size);
                return 0;
            }
        }
    }

    // 2. Choose free slot or LRU victim
    u32 victim = 0;
    u64 oldest = UINT64_MAX;
    bool found_free = false;
    for (u32 i = 0; i < NUPVFS_MAX_SLOTS; i++) {
        if (!g_slots[i].in_use) {
            victim = i;
            found_free = true;
            break;
        }
        if (g_slots[i].last_use < oldest) {
            oldest = g_slots[i].last_use;
            victim = i;
        }
    }
    if (!found_free && g_slots[victim].in_use) {
        vfsRomfsDestroy(&g_slots[victim].romfs);
        memset(&g_slots[victim], 0, sizeof(g_slots[victim]));
    }

    // Build RomFS tables inside plugin heap (capped so giant RomFS games bail fast)
    VfsRomfs tmp = {};
    const bool ok = vfsRomfsBuildLayered(&tmp, &g_sd, paths[0], ov_cnt ? ov_ptrs : NULL, ov_cnt);
    if (!ok) {
        mutexUnlock(&g_vfs_lock);
        nupLogf("[nupvfs] MountRomfs SKIP (plugin cap/fallback) key='%s'\n", key);
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }

    g_slots[victim].in_use = true;
    g_slots[victim].last_use = ++g_slot_clock;
    g_slots[victim].title_id = req->title_id;
    g_slots[victim].prog_idx = req->prog_idx;
    snprintf(g_slots[victim].key, sizeof(g_slots[victim].key), "%s", key);
    g_slots[victim].romfs = tmp;
    g_slots[victim].romfs.sd = &g_sd;

    out->slot_id = victim + 1u;
    out->cached = 0u;
    out->total_size = vfsRomfsSize(&g_slots[victim].romfs);
    mutexUnlock(&g_vfs_lock);

    nupLogf("[nupvfs] MountRomfs BUILT slot=%u layers=%u size=0x%llx key='%s'\n",
            out->slot_id, active_layers, (unsigned long long)out->total_size, key);
    return 0;
}

static Result cmd_read_romfs(const NupVfsReadReq* req, void* dst, size_t dst_sz, u64* out_got) {
    *out_got = 0;
    if (!req || !dst || !dst_sz || req->slot_id == 0 || req->slot_id > NUPVFS_MAX_SLOTS)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    const u64 want = req->size < (u64)dst_sz ? req->size : (u64)dst_sz;

    mutexLock(&g_vfs_lock);
    VfsSlot* s = &g_slots[req->slot_id - 1u];
    if (!s->in_use) {
        mutexUnlock(&g_vfs_lock);
        return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }
    s->last_use = ++g_slot_clock;
    const Result rc = vfsRomfsRead(&s->romfs, req->offset, dst, want, out_got);
    mutexUnlock(&g_vfs_lock);
    return rc;
}

// --- GameChat (C) Button -> HBMenu Watcher Thread ---

static u32 g_cbutton_events = 0;
static u32 g_cbutton_rc = 0;

static u64 read_cbutton_donor_tid(void) {
    if (!g_sd_ready)
        return 0;
    FsFile f = {};
    if (R_FAILED(fsFsOpenFile(&g_sd, "/kaihen/cbutton.cfg", FsOpenMode_Read, &f)))
        return 0;
    char buf[256] = {};
    u64 got = 0;
    fsFileRead(&f, 0, buf, sizeof(buf) - 1, FsReadOption_None, &got);
    fsFileClose(&f);
    if (!got)
        return 0;
    char* p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == '#') {
            while (*p && *p != '\n') p++;
            continue;
        }
        if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        u64 val = 0;
        int digits = 0;
        while (*p) {
            char c = *p;
            u64 d = 0;
            if (c >= '0' && c <= '9') d = (u64)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (u64)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (u64)(c - 'A' + 10);
            else break;
            val = (val << 4) | d;
            digits++;
            p++;
        }
        if (digits == 16)
            return val;
        while (*p && *p != '\n') p++;
    }
    return 0;
}

static Result open_hen_from_plugin(Service* out_hen) {
    Service ro = {};
    Result rc = smGetService(&ro, "ldr:ro");
    if (R_FAILED(rc))
        return rc;
    // Initialize ldr:ro for our own process so RO accepts GetHomebrewSession
    const u64 pid_placeholder = 0;
    serviceDispatchIn(&ro, 4, pid_placeholder,
        .in_send_pid = true,
        .in_num_handles = 1,
        .in_handles = { CUR_PROCESS_HANDLE });
    rc = kaihenOpenHomebrewSession(&ro, out_hen);
    serviceClose(&ro);
    return rc;
}

static void trigger_cbutton_hbmenu(void) {
    if (!g_settings[5].value)
        return; // C Button -> HBMenu toggled Off in Settings -> Plugins

    __atomic_fetch_add(&g_cbutton_events, 1u, __ATOMIC_RELAXED);
    nupLogf("[cbutton] C button triggered -> arming HBMenu ONLY (never a backup game)\n");

    Service hen = {};
    Result rc = open_hen_from_plugin(&hen);
    if (R_FAILED(rc)) {
        nupLogf("[cbutton] open_hen_from_plugin failed: 0x%x\n", rc);
        return;
    }

    // 1. Always clear any backup-game next.nsp override so C button ONLY boots HBMenu
    const Result clr_rc = serviceDispatch(&hen, HEN_CMD_CLEAR_NEXT_PACKAGE);
    // 2. Auto-arm GameArm for /kaihen/bin/game/exefs.nsp (HBMenu) without holding R
    const Result arm_rc = serviceDispatch(&hen, HEN_CMD_ARM_NEXT_LAUNCH);

    // 3. Visual feedback toast ("Ready to play!") on HOME overlay
    struct {
        u32 operation;
        u32 body_size;
        u8 body[120];
    } notif = { 5002u /* ReadyToPlay */, 0u, {0} };
    serviceDispatchIn(&hen, 24 /* SendNotification */, notif);
    serviceClose(&hen);

    nupLogf("[cbutton] ClearNextPackage=0x%x ArmNextLaunch=0x%x\n", clr_rc, arm_rc);

    // 4. Optional immediate donor launch if configured in /kaihen/cbutton.cfg and idle on HOME
    const u64 donor_tid = read_cbutton_donor_tid();
    if (donor_tid) {
        u64 app_pid = 0;
        bool app_running = false;
        Service pmdmnt = {};
        if (R_SUCCEEDED(smGetService(&pmdmnt, "pm:dmnt"))) {
            const Result prc = serviceDispatchOut(&pmdmnt, 65000 /* GetApplicationProcessId */, app_pid);
            app_running = R_SUCCEEDED(prc) && app_pid != 0;
            serviceClose(&pmdmnt);
        }
        if (!app_running) {
            // Try pglLaunchProgram only if user explicitly configured a donor TID
            // Note: Switch 2 HOME apps normally launch via AM/qlaunch; log result for verification
            nupLogf("[cbutton] donor_tid=%016llx configured (idle on HOME, GameArm armed for HBMenu)\n",
                    (unsigned long long)donor_tid);
        } else {
            nupLogf("[cbutton] app pid=%llu already running; GameArm armed for next HBMenu launch\n",
                    (unsigned long long)app_pid);
        }
    }
}

typedef struct {
    Handle control_session;
    Handle stop_write;
    Handle stop_read;
    Handle wake_write;
    Handle wake_read;
    Mutex sessions_lock;
    Handle sessions[MAX_CLIENT_SESSIONS];
} VfsServer;

static VfsServer g_srv = {};

static void cbutton_thread_fn(void* arg) {
    (void)arg;
    // Wait 15s so kaiHEN bootstrap, other plugins, GameArm, and AM/HID finish boot cleanly
    svcSleepThread(15000000000ULL);
    nupLogf("[cbutton] opening hid:sys...\n");

    Service hid_sys = {};
    Result rc = smGetService(&hid_sys, "hid:sys");
    if (R_FAILED(rc)) {
        __atomic_store_n(&g_cbutton_rc, rc, __ATOMIC_RELEASE);
        nupLogf("[cbutton] smGetService('hid:sys') failed: 0x%x\n", rc);
        return;
    }

    // Switch 2 hid:sys cmd 171: AcquireCButtonEventHandle(u64 aruid, SendPid) -> copy event handle
    nupLogf("[cbutton] calling hid:sys cmd 171...\n");
    Handle cbtn_evt = INVALID_HANDLE;
    const u64 aruid = 0;
    rc = serviceDispatchIn(&hid_sys, 171, aruid,
        .in_send_pid = true,
        .out_handle_attrs = { SfOutHandleAttr_HipcCopy },
        .out_handles = &cbtn_evt);
    __atomic_store_n(&g_cbutton_rc, rc, __ATOMIC_RELEASE);
    if (R_FAILED(rc) || cbtn_evt == INVALID_HANDLE) {
        nupLogf("[cbutton] hid:sys cmd 171 (AcquireCButtonEventHandle) rc=0x%x\n", rc);
        serviceClose(&hid_sys);
        return;
    }

    // Switch 2 hid:sys cmd 181: ActivateCButton(u64 aruid, SendPid)
    const Result act_rc = serviceDispatchIn(&hid_sys, 181, aruid, .in_send_pid = true);
    nupLogf("[cbutton] hid:sys C-button listener active! evt=0x%x activate=0x%x\n", cbtn_evt, act_rc);

    const Handle waits[2] = { g_srv.stop_read, cbtn_evt };
    for (;;) {
        s32 idx = -1;
        const Result wrc = svcWaitSynchronization(&idx, waits, 2, UINT64_MAX);
        if (R_FAILED(wrc) || idx == 0)
            break;
        if (idx == 1) {
            svcClearEvent(cbtn_evt);
            trigger_cbutton_hbmenu();
            // 600ms debounce so a single C press fires once
            svcSleepThread(600000000ULL);
            svcClearEvent(cbtn_evt);
        }
    }

    svcCloseHandle(cbtn_evt);
    serviceClose(&hid_sys);
}

// --- Custom Multi-Session HIPC/CMIF Server (supports HipcMapAlias A/B buffers + PluginSettings) ---

static void write_cmif_reply(void* msg, Result rc, const void* data, size_t data_sz,
                             const Handle* copy_handles, u32 num_copy) {
    memset(msg, 0, IPC_MSG_SIZE);
    const u32 words = (u32)((0x10u + sizeof(CmifOutHeader) + data_sz + 3u) / 4u);
    HipcRequest reply = hipcMakeRequestInline(msg,
        .num_data_words = words,
        .num_copy_handles = num_copy);
    for (u32 i = 0; i < num_copy; i++)
        reply.copy_handles[i] = copy_handles[i];
    CmifOutHeader* hdr = (CmifOutHeader*)cmifGetAlignedDataStart(reply.data_words, msg);
    hdr->magic = CMIF_OUT_HEADER_MAGIC;
    hdr->result = rc;
    if (data && data_sz)
        memcpy(hdr + 1, data, data_sz);
}

static Result send_reply(Handle session) {
    s32 idx = -1;
    const Result rc = svcReplyAndReceive(&idx, NULL, 0, session, 0);
    return rc == KERNELRESULT(TimedOut) ? 0 : rc;
}

static void close_req_handles(const HipcParsedRequest* p) {
    for (u32 i = 0; i < p->meta.num_copy_handles; i++)
        svcCloseHandle(p->data.copy_handles[i]);
    for (u32 i = 0; i < p->meta.num_move_handles; i++)
        svcCloseHandle(p->data.move_handles[i]);
}

static void control_thread_fn(void* arg) {
    (void)arg;
    const Handle handles[2] = { g_srv.control_session, g_srv.stop_read };
    for (;;) {
        s32 idx = -1;
        Result rc = svcReplyAndReceive(&idx, handles, 2, INVALID_HANDLE, UINT64_MAX);
        if (rc == KERNELRESULT(ConnectionClosed) || R_FAILED(rc) || idx == 1)
            return;

        void* msg = armGetTls();
        const HipcParsedRequest p = hipcParseRequest(msg);
        const CmifInHeader* hdr = (const CmifInHeader*)cmifGetAlignedDataStart(p.data.data_words, msg);
        const u8* end = (const u8*)(p.data.data_words + p.meta.num_data_words);
        const bool valid = end <= (const u8*)msg + IPC_MSG_SIZE &&
                           (const u8*)(hdr + 1) <= end &&
                           hdr->magic == CMIF_IN_HEADER_MAGIC;

        Handle client = INVALID_HANDLE;
        Result out_rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
        if (valid && p.meta.type == CmifCommandType_Request &&
            hdr->command_id == HEN_PLUGIN_CONTROL_CREATE_SESSION) {
            out_rc = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            mutexLock(&g_srv.sessions_lock);
            for (u32 s = 0; s < MAX_CLIENT_SESSIONS; s++) {
                if (g_srv.sessions[s] == INVALID_HANDLE) {
                    out_rc = svcCreateSession(&g_srv.sessions[s], &client, false, 0);
                    break;
                }
            }
            mutexUnlock(&g_srv.sessions_lock);
            if (R_SUCCEEDED(out_rc))
                svcSignalEvent(g_srv.wake_write);
        }
        close_req_handles(&p);

        if (R_SUCCEEDED(out_rc))
            write_cmif_reply(msg, 0, NULL, 0, &client, 1);
        else
            write_cmif_reply(msg, out_rc, NULL, 0, NULL, 0);

        rc = send_reply(g_srv.control_session);
        if (client != INVALID_HANDLE)
            svcCloseHandle(client);
        if (rc == KERNELRESULT(ConnectionClosed) || R_FAILED(rc))
            return;
    }
}

static Result serve_client_request(Handle session) {
    void* msg = armGetTls();
    // Snapshot incoming HIPC/CMIF message onto stack before making any SD IPC calls
    u8 snap[IPC_MSG_SIZE];
    memcpy(snap, msg, sizeof(snap));

    const HipcParsedRequest p = hipcParseRequest(snap);
    const CmifInHeader* hdr = (const CmifInHeader*)cmifGetAlignedDataStart(p.data.data_words, snap);
    const u8* in_data = (const u8*)(hdr + 1);
    const u8* end = (const u8*)(p.data.data_words + p.meta.num_data_words);
    const bool valid = end <= snap + IPC_MSG_SIZE && in_data <= end &&
                       hdr->magic == CMIF_IN_HEADER_MAGIC && hdr->version <= 1;

    close_req_handles(&p);

    if (valid && p.meta.type == CmifCommandType_Control && hdr->command_id == 3u) {
        const u16 psz = 0;
        write_cmif_reply(msg, 0, &psz, sizeof(psz), NULL, 0);
        return send_reply(session);
    }

    if (!valid || (p.meta.type != CmifCommandType_Request &&
                   p.meta.type != CmifCommandType_RequestWithContext)) {
        write_cmif_reply(msg, MAKERESULT(Module_Libnx, LibnxError_BadInput), NULL, 0, NULL, 0);
        return send_reply(session);
    }

    const u32 cmd = hdr->command_id;
    const size_t in_sz = (size_t)(end - in_data);

    // 1. Live settings commands for ounce-hbmenu Settings -> Plugins
    if (cmd == KaihenPluginSettingsCommand_GetInfo ||
        cmd == KaihenPluginSettingsCommand_GetSetting ||
        cmd == KaihenPluginSettingsCommand_SetSetting) {
        u8 out_buf[KAIHEN_PLUGIN_MESSAGE_SIZE] = {};
        size_t out_sz = 0;
        const Result rc = kaihenPluginSettingsHandle(&g_settings_table, cmd,
                                                     in_sz ? in_data : NULL, in_sz,
                                                     out_buf, &out_sz);
        write_cmif_reply(msg, rc, out_buf, R_SUCCEEDED(rc) ? out_sz : 0, NULL, 0);
        return send_reply(session);
    }

    // 2. VFS commands (support HipcMapAlias A/B buffers)
    switch (cmd) {
    case NupVfsCmd_GetInfo: {
        NupVfsInfo info = {
            .magic = NUPVFS_MAGIC,
            .version = NUPVFS_VERSION,
            .slot_count = count_used_slots(),
            .flags = settings_flags(),
            .cbutton_events = __atomic_load_n(&g_cbutton_events, __ATOMIC_RELAXED),
            .cbutton_rc = __atomic_load_n(&g_cbutton_rc, __ATOMIC_ACQUIRE),
        };
        write_cmif_reply(msg, 0, &info, sizeof(info), NULL, 0);
        return send_reply(session);
    }
    case NupVfsCmd_MountRomfs: {
        NupVfsMountReply rep = {};
        Result rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
        if (in_sz >= sizeof(NupVfsMountReq) && p.meta.num_send_buffers >= 1) {
            NupVfsMountReq req = {};
            memcpy(&req, in_data, sizeof(req));
            const void* abuf = hipcGetBufferAddress(&p.data.send_buffers[0]);
            const size_t asz = hipcGetBufferSize(&p.data.send_buffers[0]);
            rc = cmd_mount_romfs(&req, (const u8*)abuf, asz, &rep);
        }
        write_cmif_reply(msg, rc, &rep, R_SUCCEEDED(rc) ? sizeof(rep) : 0, NULL, 0);
        return send_reply(session);
    }
    case NupVfsCmd_ReadRomfs: {
        u64 got = 0;
        Result rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
        if (in_sz >= sizeof(NupVfsReadReq) && p.meta.num_recv_buffers >= 1) {
            NupVfsReadReq req = {};
            memcpy(&req, in_data, sizeof(req));
            void* bbuf = hipcGetBufferAddress(&p.data.recv_buffers[0]);
            const size_t bsz = hipcGetBufferSize(&p.data.recv_buffers[0]);
            rc = cmd_read_romfs(&req, bbuf, bsz, &got);
        }
        write_cmif_reply(msg, rc, &got, R_SUCCEEDED(rc) ? sizeof(got) : 0, NULL, 0);
        return send_reply(session);
    }
    case NupVfsCmd_ClearCache: {
        clear_all_slots();
        write_cmif_reply(msg, 0, NULL, 0, NULL, 0);
        return send_reply(session);
    }
    case NupVfsCmd_SetActiveGame: {
        Result rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
        if (in_sz >= sizeof(NupVfsActiveGame) && p.meta.num_send_buffers >= 1) {
            mutexLock(&g_vfs_lock);
            memcpy(&g_active_game, in_data, sizeof(g_active_game));
            const void* abuf = hipcGetBufferAddress(&p.data.send_buffers[0]);
            const size_t asz = hipcGetBufferSize(&p.data.send_buffers[0]);
            const size_t n = asz < sizeof(g_active_path) - 1 ? asz : sizeof(g_active_path) - 1;
            memcpy(g_active_path, abuf, n);
            g_active_path[n] = '\0';
            mutexUnlock(&g_vfs_lock);
            nupLogf("[nupvfs] SetActiveGame tid=%016llx prog=%u path='%s'\n",
                    (unsigned long long)g_active_game.title_id, g_active_game.prog_idx, g_active_path);
            rc = 0;
        }
        write_cmif_reply(msg, rc, NULL, 0, NULL, 0);
        return send_reply(session);
    }
    case NupVfsCmd_GetActiveGame: {
        NupVfsActiveGame out_g = {};
        mutexLock(&g_vfs_lock);
        out_g = g_active_game;
        out_g.flags = settings_flags();
        if (p.meta.num_recv_buffers >= 1) {
            void* bbuf = hipcGetBufferAddress(&p.data.recv_buffers[0]);
            const size_t bsz = hipcGetBufferSize(&p.data.recv_buffers[0]);
            if (bbuf && bsz) {
                memset(bbuf, 0, bsz);
                snprintf((char*)bbuf, bsz, "%s", g_active_path);
            }
        }
        mutexUnlock(&g_vfs_lock);
        write_cmif_reply(msg, 0, &out_g, sizeof(out_g), NULL, 0);
        return send_reply(session);
    }
    default:
        write_cmif_reply(msg, MAKERESULT(Module_Libnx, LibnxError_BadInput), NULL, 0, NULL, 0);
        return send_reply(session);
    }
}

static void run_worker_loop(void) {
    Handle waits[2 + MAX_CLIENT_SESSIONS];
    u32 slots[2 + MAX_CLIENT_SESSIONS];

    for (;;) {
        waits[0] = g_srv.stop_read;
        waits[1] = g_srv.wake_read;
        s32 count = 2;

        mutexLock(&g_srv.sessions_lock);
        for (u32 s = 0; s < MAX_CLIENT_SESSIONS; s++) {
            if (g_srv.sessions[s] != INVALID_HANDLE) {
                waits[count] = g_srv.sessions[s];
                slots[count] = s;
                count++;
            }
        }
        mutexUnlock(&g_srv.sessions_lock);

        s32 idx = -1;
        Result rc = svcReplyAndReceive(&idx, waits, count, INVALID_HANDLE, UINT64_MAX);
        if (idx == 0 && R_SUCCEEDED(rc))
            return;
        if (idx == 1 && R_SUCCEEDED(rc)) {
            svcClearEvent(g_srv.wake_read);
            continue;
        }
        if (idx < 2 || idx >= count) {
            if (R_FAILED(rc))
                return;
            continue;
        }

        const u32 slot = slots[idx];
        if (rc == KERNELRESULT(ConnectionClosed)) {
            mutexLock(&g_srv.sessions_lock);
            svcCloseHandle(g_srv.sessions[slot]);
            g_srv.sessions[slot] = INVALID_HANDLE;
            mutexUnlock(&g_srv.sessions_lock);
            continue;
        }
        if (R_FAILED(rc))
            return;

        if (hipcParseRequest(armGetTls()).meta.type == CmifCommandType_Close) {
            mutexLock(&g_srv.sessions_lock);
            svcCloseHandle(g_srv.sessions[slot]);
            g_srv.sessions[slot] = INVALID_HANDLE;
            mutexUnlock(&g_srv.sessions_lock);
            continue;
        }

        rc = serve_client_request(g_srv.sessions[slot]);
        if (rc == KERNELRESULT(ConnectionClosed)) {
            mutexLock(&g_srv.sessions_lock);
            svcCloseHandle(g_srv.sessions[slot]);
            g_srv.sessions[slot] = INVALID_HANDLE;
            mutexUnlock(&g_srv.sessions_lock);
        }
    }
}

int main(void) {
    mutexInit(&g_log_lock);
    mutexInit(&g_vfs_lock);
    mutexInit(&g_srv.sessions_lock);

    Handle ready_event = INVALID_HANDLE;
    Result rc = pluginRuntimeInitializeWithService(&ready_event, &g_srv.control_session);
    if (R_FAILED(rc))
        return (int)rc;

    rc = svcCreateEvent(&g_srv.stop_write, &g_srv.stop_read);
    if (R_SUCCEEDED(rc))
        rc = svcCreateEvent(&g_srv.wake_write, &g_srv.wake_read);

    Thread ctrl_thread = {};
    Thread cbtn_thread = {};
    bool ctrl_started = false;
    bool cbtn_started = false;

    if (R_SUCCEEDED(rc)) {
        if (R_SUCCEEDED(threadCreate(&ctrl_thread, control_thread_fn, NULL, NULL,
                                     PLUGIN_THREAD_STACK, PLUGIN_THREAD_PRIO, -2)) &&
            R_SUCCEEDED(threadStart(&ctrl_thread))) {
            ctrl_started = true;
        }
    }

    // Signal bootstrap ready IMMEDIATELY before touching setsys/fs/SD/hid so
    // nupvfs can never delay PluginReady or contend with bootstrap FS/RO handoff.
    svcSignalEvent(ready_event);

    // Let bootstrap finish remaining plugins, plugin-status.txt, RO connect, and GameArm.
    svcSleepThread(3000000000ULL);

    // Match ouncerpc.nso: populate hosversion before fsInitialize().
    if (R_SUCCEEDED(setsysInitialize())) {
        SetSysFirmwareVersion fw = {};
        if (R_SUCCEEDED(setsysGetFirmwareVersion(&fw)))
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        setsysExit();
    }

    bool fs_inited = false;
    if (R_SUCCEEDED(fsInitialize())) {
        fs_inited = true;
        if (R_SUCCEEDED(fsOpenSdCardFileSystem(&g_sd))) {
            g_sd_ready = true;
            settings_load();
            nupLogf("=== nupvfs.nso started (heap=8MiB games=%u mods=%u trace=%u cache=%u native=%u cbutton=%u) ===\n",
                    (unsigned)g_settings[0].value, (unsigned)g_settings[1].value,
                    (unsigned)g_settings[2].value, (unsigned)g_settings[3].value,
                    (unsigned)g_settings[4].value, (unsigned)g_settings[5].value);
        }
    }

    if (ctrl_started) {
        if (R_SUCCEEDED(threadCreate(&cbtn_thread, cbutton_thread_fn, NULL, NULL,
                                     PLUGIN_THREAD_STACK, CBUTTON_THREAD_PRIO, -2)) &&
            R_SUCCEEDED(threadStart(&cbtn_thread))) {
            cbtn_started = true;
        }
        run_worker_loop();
    }

    svcSignalEvent(g_srv.stop_write);
    if (ctrl_started) {
        threadWaitForExit(&ctrl_thread);
        threadClose(&ctrl_thread);
    }
    if (cbtn_started) {
        threadWaitForExit(&cbtn_thread);
        threadClose(&cbtn_thread);
    }

    clear_all_slots();
    mutexLock(&g_srv.sessions_lock);
    for (u32 s = 0; s < MAX_CLIENT_SESSIONS; s++) {
        if (g_srv.sessions[s] != INVALID_HANDLE) {
            svcCloseHandle(g_srv.sessions[s]);
            g_srv.sessions[s] = INVALID_HANDLE;
        }
    }
    mutexUnlock(&g_srv.sessions_lock);
    if (g_srv.wake_write) svcCloseHandle(g_srv.wake_write);
    if (g_srv.wake_read) svcCloseHandle(g_srv.wake_read);
    if (g_srv.stop_write) svcCloseHandle(g_srv.stop_write);
    if (g_srv.stop_read) svcCloseHandle(g_srv.stop_read);
    if (g_sd_ready)
        fsFsClose(&g_sd);
    if (fs_inited)
        fsExit();
    pluginRuntimeExit();
    return 0;
}
