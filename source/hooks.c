// SPDX-License-Identifier: MIT
#include "hooks.h"
#include "elf_loader.h"
#include "log.h"
#include "trace.h"

#include <string.h>

#define MAX_VFS_MOUNTS 32
#define MAX_OPEN_FILES 1024
#define MAX_OPEN_DIRS  256
#define MAX_DLC_ENTRIES 64

#define NN_FS_PATH_NOT_FOUND        MAKERESULT(2, 1)
#define NN_FS_PATH_ALREADY_EXISTS   MAKERESULT(2, 2)
#define NN_FS_INVALID_ARG           MAKERESULT(2, 6002)
#define NN_FS_UNSUPPORTED_OPERATION MAKERESULT(2, 6300)

typedef struct {
    void* handle;
} NnFileHandle;

typedef struct {
    void* handle;
} NnDirHandle;

typedef struct {
    char name[0x301];
    u8 pad0[3];
    u8 type;
    u8 pad1[3];
    s64 file_size;
} NnDirectoryEntry;

_Static_assert(sizeof(NnDirectoryEntry) == 0x310, "NnDirectoryEntry size");

typedef enum {
    MOUNT_NONE = 0,
    MOUNT_ROM_NUP,
    MOUNT_SD_RO,
    MOUNT_SD_RW,
} VfsMountKind;

typedef struct {
    VfsMountKind kind;
    char name[32];
    u32 nup_root_dir;
    char sd_root[0x300];
    bool has_overlay;
    char sd_overlay[0x300];
} VfsMount;

typedef struct {
    int index;
    bool is_nup;
    u32 nup_dir_idx;
    char sd_root[0x300];
} DlcEntry;

typedef struct {
    bool in_use;
    bool is_raw;
    bool is_rw;
    int open_mode;
    u32 file_idx;
    FsFile raw_file;
    s64 raw_size;
} OpenNupFile;

typedef struct {
    bool in_use;
    bool is_raw;
    bool eof_logged;
    u32 dir_idxs[NUP_MAX_ROMFS_LAYERS];
    u32 dir_count;
    u32 layer_pos;
    u32 cursor;
    int mode;
    FsDir raw_dir;
} OpenNupDir;

static NupArchive* g_nup = NULL;
static FsFileSystem* g_sd = NULL;
static u64 g_title_id = 0;
static NupRuntimeCapabilities g_caps = {};
static Handle g_hen_sm = INVALID_HANDLE;
static Handle g_preopened_nv = INVALID_HANDLE;

static VfsMount g_mounts[MAX_VFS_MOUNTS] = {};
static OpenNupFile g_files[MAX_OPEN_FILES] = {};
static OpenNupDir g_dirs[MAX_OPEN_DIRS] = {};
static DlcEntry g_dlcs[MAX_DLC_ENTRIES] = {};
static int g_dlc_count = 0;
static bool g_has_rom_overlay = false;
static char g_rom_overlay_root[0x300] = {};
static NupSpinLock g_handle_lock;

static u32 (*real_Unmount)(const char*) = NULL;
static bool (*real_IsMounted)(const char*) = NULL;
static bool (*real_IsPathMounted)(const char*) = NULL;
static u32 (*real_OpenFile)(NnFileHandle*, const char*, int) = NULL;
static u32 (*real_ReadFile4)(NnFileHandle, s64, void*, size_t) = NULL;
static u32 (*real_ReadFile5Opt)(NnFileHandle, s64, void*, size_t, const void*) = NULL;
static u32 (*real_ReadFile5Out)(size_t*, NnFileHandle, s64, void*, size_t) = NULL;
static u32 (*real_ReadFile6)(size_t*, NnFileHandle, s64, void*, size_t, const void*) = NULL;
static u32 (*real_ReadFileAtOnce)(const char*, void*, size_t) = NULL;
static u32 (*real_WriteFile)(NnFileHandle, s64, const void*, size_t, const void*) = NULL;
static u32 (*real_FlushFile)(NnFileHandle) = NULL;
static u32 (*real_SetFileSize)(NnFileHandle, s64) = NULL;
static u32 (*real_GetFileSize)(s64*, NnFileHandle) = NULL;
static int (*real_GetFileOpenMode)(NnFileHandle) = NULL;
static void (*real_CloseFile)(NnFileHandle) = NULL;
static u32 (*real_CreateFile2)(const char*, s64) = NULL;
static u32 (*real_CreateFile3)(const char*, s64, int) = NULL;
static u32 (*real_CreateAndWriteFileAtOnce)(const char*, const void*, size_t) = NULL;
static u32 (*real_DeleteFile)(const char*) = NULL;
static u32 (*real_RenameFile)(const char*, const char*) = NULL;
static u32 (*real_CreateDirectory)(const char*) = NULL;
static u32 (*real_DeleteDirectory)(const char*) = NULL;
static u32 (*real_DeleteDirectoryRec)(const char*) = NULL;
static u32 (*real_CleanDirectoryRec)(const char*) = NULL;
static u32 (*real_RenameDirectory)(const char*, const char*) = NULL;
static u32 (*real_GetFreeSpaceSize)(s64*, const char*) = NULL;
static u32 (*real_GetTotalSpaceSize)(s64*, const char*) = NULL;
static u32 (*real_Commit1)(const char*) = NULL;
static u32 (*real_Commit2)(const char*, const void*) = NULL;
static u32 (*real_CommitMulti)(const char* const*, int) = NULL;
static u32 (*real_CommitSaveData)(const char*) = NULL;
static u32 (*real_GetEntryType)(u32*, const char*) = NULL;
static u32 (*real_OpenDirectory)(NnDirHandle*, const char*, int) = NULL;
static u32 (*real_ReadDirectory)(s64*, NnDirectoryEntry*, NnDirHandle, s64) = NULL;
static u32 (*real_GetDirEntryCount)(s64*, NnDirHandle) = NULL;
static void (*real_CloseDirectory)(NnDirHandle) = NULL;
static u32 (*real_GetServiceHandle)(u32*, const char*, size_t) = NULL;
static void (*real_ViInitialize)(void) = NULL;
static u32 (*real_ViOpenDefaultDisplay)(void**) = NULL;
static u32 (*real_ViCreateLayer)(void**, void*) = NULL;
static void* (*real_NvnBootstrapLoader)(const char*) = NULL;
static u32 (*real_SetMemoryHeapSize)(size_t) = NULL;
static void (*real_QueryMemoryInfo)(void*) = NULL;
static bool (*real_IsVamEnabled)(void) = NULL;
static u32 (*real_AllocAddrRegion)(u64*, size_t) = NULL;
static u32 (*real_AllocMemPages)(u64, size_t) = NULL;
static u32 (*real_FreeMemPages)(u64, size_t) = NULL;
static u32 (*real_CreateThread6)(void*, void (*)(void*), void*, void*, size_t, int) = NULL;
static u32 (*real_CreateThread7)(void*, void (*)(void*), void*, void*, size_t, int, int) = NULL;
static bool (*real_MapAliasStack)(const void*, void**, const void*, size_t) = NULL;
static void (*real_SetThreadName)(void*, const char*) = NULL;
static void (*real_SetThreadNamePtr)(void*, const char*) = NULL;
static void (*real_init_libc1)(void) = NULL;
static void (*real_init_sdk_mod)(void) = NULL;
static void (*real_OeInitApplet)(void) = NULL;
static bool (*real_AmInitAppInterfaces)(void) = NULL;
static u32 (*real_SmFinalize)(void) = NULL;
static void (*real_AttachSysEvent)(void*, u32, bool, int) = NULL;
static void (*real_SetupGpuErrorHandler)(void) = NULL;
static void (*real_WaitSystemEvent)(void*) = NULL;
static int (*real_GetCurrentFocusState)(void) = NULL;
static void (*real_SetFocusHandlingMode)(int) = NULL;
static void (*real_nninitStartup)(void) = NULL;
static void (*real_nnMain)(void) = NULL;
static void (*real_AbortImpl0)(void) = NULL;
static void (*real_AbortImplRes)(const u32*) = NULL;
static void (*real_StdTerminate)(void) = NULL;
static void (*real_AssertFail)(const char*, const char*, int, const char*) = NULL;
static void (*real_LibcppVerboseAbort)(const char*, ...) = NULL;
static void (*real_ThrowSystemError)(int, const char*) = NULL;
static void (*real_StdAllocInit2)(void*, void*, size_t) = NULL;
static void (*real_StdAllocInit3)(void*, void*, size_t, bool) = NULL;
static void (*real_StdAllocCtor2)(void*, void*, size_t) = NULL;
static u32 (*real_RoLookupSymbol)(uintptr_t*, const char*) = NULL;
static u32 (*real_RoLookupModuleSymbol)(uintptr_t*, const void*, const char*) = NULL;
static int (*real_GetHostArgc)(void) = NULL;
static char** (*real_GetHostArgv)(void) = NULL;

extern ModuleSet g_mods;
#include "diag.h"

volatile u32 g_open_file_count = 0;
volatile u32 g_post_aov_active = 0;
volatile u64 g_aov_tid = 0;
static volatile u32 g_post_aov_logs = 0;
static u32 g_read_file_logs = 0;
static u32 g_open_dir_logs = 0;
static u32 g_entry_type_logs = 0;
static u32 g_entry_type_fail_logs = 0;
static u32 g_create_thread_logs = 0;

static u64 g_libnx_heap_used = 0;
static u64 g_game_heap_base = 0;
static u64 g_game_heap_size = 0;
static u64 g_game_heap_cursor = 0;
static u64 g_compat_heap_reserved = 0;
static bool g_compat_heap_marked = false;
static u64 g_vam_flat_used = 0;
static u64 g_vam_backed_bytes = 0;
static u32 g_std_alloc_init_logs = 0;

// --- TLS-free path formatting helpers ---

static void append_str(char* dst, size_t dst_sz, size_t* pos, const char* s) {
    if (!s) return;
    while (*s && *pos + 1 < dst_sz)
        dst[(*pos)++] = *s++;
    dst[*pos] = '\0';
}

static void append_hex64(char* dst, size_t dst_sz, size_t* pos, u64 v) {
    static const char hex[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4) {
        if (*pos + 1 < dst_sz)
            dst[(*pos)++] = hex[(v >> shift) & 0xf];
    }
    dst[*pos] = '\0';
}

static void append_i32(char* dst, size_t dst_sz, size_t* pos, int v) {
    char tmp[16];
    int n = 0;
    unsigned int uv;
    if (v < 0) {
        if (*pos + 1 < dst_sz) dst[(*pos)++] = '-';
        uv = (unsigned int)(-(v + 1)) + 1u;
    } else {
        uv = (unsigned int)v;
    }
    do {
        tmp[n++] = (char)('0' + (uv % 10u));
        uv /= 10u;
    } while (uv && n < 15);
    while (n > 0 && *pos + 1 < dst_sz)
        dst[(*pos)++] = tmp[--n];
    dst[*pos] = '\0';
}

static void format_sd_subpath(const char* root, const char* rel, char* out, size_t out_sz) {
    size_t pos = 0;
    out[0] = '\0';
    append_str(out, out_sz, &pos, root);
    while (pos > 1 && out[pos - 1] == '/')
        out[--pos] = '\0';
    if (rel) {
        while (*rel == '/')
            rel++;
        if (*rel) {
            append_str(out, out_sz, &pos, "/");
            append_str(out, out_sz, &pos, rel);
        }
    }
    if (pos == 0)
        append_str(out, out_sz, &pos, "/");
}

static void format_save_root(u64 app_id, const char* kind_sub, int idx, char* out, size_t out_sz) {
    const u64 tid = app_id ? app_id : g_title_id;
    size_t pos = 0;
    out[0] = '\0';
    append_str(out, out_sz, &pos, "/kaihen/saves/");
    append_hex64(out, out_sz, &pos, tid);
    if (kind_sub && kind_sub[0]) {
        append_str(out, out_sz, &pos, "/");
        append_str(out, out_sz, &pos, kind_sub);
    }
    if (idx >= 0) {
        append_str(out, out_sz, &pos, "_");
        append_i32(out, out_sz, &pos, idx);
    }
}

static void ensure_sd_dir_recursive(const char* path) {
    if (!g_sd || !path || path[0] != '/')
        return;
    char tmp[FS_MAX_PATH];
    size_t len = strlen(path);
    if (len >= sizeof(tmp))
        len = sizeof(tmp) - 1;
    memcpy(tmp, path, len);
    tmp[len] = '\0';
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\0') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (tmp[1] != '\0')
                nupRawFsCreateDir(g_sd, tmp);
            tmp[i] = saved;
        }
    }
}

static bool sd_dir_exists(const char* path) {
    if (!g_sd || !path || !path[0])
        return false;
    u32 et = 0;
    return R_SUCCEEDED(nupRawFsGetEntryType(g_sd, path, &et)) && et == FsDirEntryType_Dir;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int parse_dlc_index(const char* name) {
    if (!name || !name[0])
        return -1;

    // 1. 0x<hex> index (e.g. "0x1", "0x001")
    if (name[0] == '0' && (name[1] == 'x' || name[1] == 'X')) {
        const char* p = name + 2;
        if (!*p) return -1;
        int val = 0;
        while (*p) {
            int d = hex_nibble(*p++);
            if (d < 0 || val > 0x100000) return -1;
            val = (val << 4) | d;
        }
        return val > 0 ? val : -1;
    }

    // 2. Pure decimal index (e.g. "1", "001", "12") — skip 16-digit IDs handled below
    const size_t len = strlen(name);
    if (len < 16) {
        bool all_dec = true;
        int val = 0;
        for (size_t i = 0; i < len; i++) {
            if (name[i] < '0' || name[i] > '9') { all_dec = false; break; }
            if (val > 1000000) { all_dec = false; break; }
            val = val * 10 + (name[i] - '0');
        }
        if (all_dec)
            return val > 0 ? val : -1;
    }

    // 3. 16-hex Title ID anywhere in name (e.g. "0100453019AA9001" or "Pack [0100453019AA9001]")
    for (size_t i = 0; i + 16 <= len; i++) {
        u64 tid = 0;
        bool ok = true;
        for (size_t j = 0; j < 16; j++) {
            int d = hex_nibble(name[i + j]);
            if (d < 0) { ok = false; break; }
            tid = (tid << 4) | (u64)d;
        }
        if (ok && (i == 0 || hex_nibble(name[i - 1]) < 0) &&
            (i + 16 == len || hex_nibble(name[i + 16]) < 0)) {
            int idx = (int)(tid & 0xFFFull);
            if (idx > 0)
                return idx;
        }
    }

    return -1;
}

static void add_dlc_entry(int idx, const char* root_path) {
    for (int i = 0; i < g_dlc_count; i++) {
        if (g_dlcs[i].index == idx)
            return;
    }
    if (g_dlc_count >= MAX_DLC_ENTRIES)
        return;
    g_dlcs[g_dlc_count].index = idx;
    g_dlcs[g_dlc_count].is_nup = false;
    g_dlcs[g_dlc_count].nup_dir_idx = 0;
    strncpy(g_dlcs[g_dlc_count].sd_root, root_path, sizeof(g_dlcs[g_dlc_count].sd_root) - 1);
    g_dlcs[g_dlc_count].sd_root[sizeof(g_dlcs[g_dlc_count].sd_root) - 1] = '\0';
    g_dlc_count++;
}

static void add_dlc_entry_nup(int idx, u32 dir_idx) {
    for (int i = 0; i < g_dlc_count; i++) {
        if (g_dlcs[i].index == idx)
            return;
    }
    if (g_dlc_count >= MAX_DLC_ENTRIES)
        return;
    g_dlcs[g_dlc_count].index = idx;
    g_dlcs[g_dlc_count].is_nup = true;
    g_dlcs[g_dlc_count].nup_dir_idx = dir_idx;
    g_dlcs[g_dlc_count].sd_root[0] = '\0';
    g_dlc_count++;
}

static u32 resolve_nup_dlc_dir(u32 sub_dir_idx) {
    bool is_dir = false;
    u32 idx = 0;
    if (nupLookupInDir(g_nup, sub_dir_idx, "romfs", &is_dir, &idx) && is_dir)
        return idx;
    if (nupLookupInDir(g_nup, sub_dir_idx, "0/romfs", &is_dir, &idx) && is_dir)
        return idx;
    const NupDirEntry* d = &g_nup->dirs[sub_dir_idx];
    for (u32 i = 0; i < d->child_count; i++) {
        const u32 node = g_nup->children[d->first_child + i];
        if (node < g_nup->dir_count) {
            if (nupLookupInDir(g_nup, node, "romfs", &is_dir, &idx) && is_dir)
                return idx;
        }
    }
    return sub_dir_idx;
}

static void scan_dlc_in_nup(void) {
    if (!g_nup || g_nup->is_raw || !g_nup->open)
        return;

    // 1. Native multi-partition NUP DLC entries (pure DLC with no exefs of its own)
    for (u32 pi = 0; pi < g_nup->part_count; pi++) {
        const NupPartEntry* pe = &g_nup->parts[pi];
        if (pe->kind == 2 && pe->exefs_dir_idx >= g_nup->dir_count &&
            pe->romfs_dir_idx < g_nup->dir_count) {
            const int idx = (int)(pe->title_id & 0xFFFull);
            if (idx > 0)
                add_dlc_entry_nup(idx, pe->romfs_dir_idx);
        }
    }

    // 2. Fallback: explicit dlc/ directory inside TOC
    if (!g_nup->has_dlc)
        return;
    bool is_dir = false;
    const u32 dlc_root = g_nup->dlc_dir_idx;
    u32 direct_romfs = 0;
    if (nupLookupInDir(g_nup, dlc_root, "romfs", &is_dir, &direct_romfs) && is_dir) {
        add_dlc_entry_nup(1, direct_romfs);
        return;
    }
    const NupDirEntry* d = &g_nup->dirs[dlc_root];
    for (u32 i = 0; i < d->child_count; i++) {
        const u32 node = g_nup->children[d->first_child + i];
        if (node >= g_nup->dir_count)
            continue;
        const NupDirEntry* cd = &g_nup->dirs[node];
        char name[128];
        const size_t n = cd->name_len < sizeof(name) - 1 ? cd->name_len : sizeof(name) - 1;
        memcpy(name, g_nup->strings + cd->name_off, n);
        name[n] = '\0';
        const int idx = parse_dlc_index(name);
        if (idx <= 0)
            continue;
        add_dlc_entry_nup(idx, resolve_nup_dlc_dir(node));
    }
}

static bool resolve_dlc_romfs_root(const char* sub, char* out, size_t out_sz) {
    char cand[0x300];
    format_sd_subpath(sub, "romfs", cand, sizeof(cand));
    if (sd_dir_exists(cand)) {
        strncpy(out, cand, out_sz - 1);
        out[out_sz - 1] = '\0';
        return true;
    }
    format_sd_subpath(sub, "0/romfs", cand, sizeof(cand));
    if (sd_dir_exists(cand)) {
        strncpy(out, cand, out_sz - 1);
        out[out_sz - 1] = '\0';
        return true;
    }
    // Check any one-level child folder containing romfs (e.g. <version>/romfs)
    FsDir d = {};
    if (R_SUCCEEDED(nupRawFsOpenDir(g_sd, sub, FsDirOpenMode_ReadDirs, &d))) {
        FsDirectoryEntry ents[16];
        s64 got = 0;
        bool found = false;
        while (!found && R_SUCCEEDED(nupRawDirRead(&d, &got, ents, 16)) && got > 0) {
            for (s64 i = 0; i < got; i++) {
                char mid[0x300];
                format_sd_subpath(sub, ents[i].name, mid, sizeof(mid));
                format_sd_subpath(mid, "romfs", cand, sizeof(cand));
                if (sd_dir_exists(cand)) {
                    strncpy(out, cand, out_sz - 1);
                    out[out_sz - 1] = '\0';
                    found = true;
                    break;
                }
            }
        }
        serviceClose(&d.s);
        if (found)
            return true;
    }
    strncpy(out, sub, out_sz - 1);
    out[out_sz - 1] = '\0';
    return true;
}

static void scan_dlc_parent(const char* parent) {
    if (!g_sd || !sd_dir_exists(parent))
        return;

    // Direct single-DLC layout: <App Name>/dlc/romfs/ -> DLC index 1
    char direct_romfs[0x300];
    format_sd_subpath(parent, "romfs", direct_romfs, sizeof(direct_romfs));
    if (sd_dir_exists(direct_romfs)) {
        add_dlc_entry(1, direct_romfs);
        return;
    }

    FsDir d = {};
    if (R_FAILED(nupRawFsOpenDir(g_sd, parent, FsDirOpenMode_ReadDirs, &d)))
        return;
    FsDirectoryEntry ents[16];
    s64 got = 0;
    while (R_SUCCEEDED(nupRawDirRead(&d, &got, ents, 16)) && got > 0) {
        for (s64 i = 0; i < got; i++) {
            const int idx = parse_dlc_index(ents[i].name);
            if (idx <= 0)
                continue;
            char sub[0x300];
            format_sd_subpath(parent, ents[i].name, sub, sizeof(sub));
            char romsub[0x300];
            resolve_dlc_romfs_root(sub, romsub, sizeof(romsub));
            add_dlc_entry(idx, romsub);
        }
    }
    serviceClose(&d.s);
}

static void sort_dlcs(void) {
    for (int i = 1; i < g_dlc_count; i++) {
        DlcEntry key = g_dlcs[i];
        int j = i - 1;
        while (j >= 0 && g_dlcs[j].index > key.index) {
            g_dlcs[j + 1] = g_dlcs[j];
            j--;
        }
        g_dlcs[j + 1] = key;
    }
}

void hooksSetNvHandle(Handle nv_session) {
    g_preopened_nv = nv_session;
}

void hooksMarkCompatHeapEnd(void) {
    if (g_compat_heap_marked)
        return;
    g_compat_heap_marked = true;
    g_compat_heap_reserved = g_game_heap_size;
    if (g_compat_heap_reserved > 0) {
        nupLogf("[mem] marked compat heap reservation: 0x%llx (excluded from app QueryMemoryInfo)\n",
                (unsigned long long)g_compat_heap_reserved);
    }
}

void hooksInit(NupArchive* nup, FsFileSystem* sd,
               const NupRuntimeCapabilities* caps, Handle hen_sm_proxy) {
    g_nup = nup;
    g_sd = sd;
    if (caps) {
        g_caps = *caps;
        g_title_id = caps->target_tid ? caps->target_tid : (nup ? nup->title_id : 0);
    } else {
        memset(&g_caps, 0, sizeof(g_caps));
        g_title_id = nup ? nup->title_id : 0;
        g_caps.target_tid = g_title_id;
        g_caps.target_is_switch1 = ((g_title_id >> 56) == 0x01);
        svcGetInfo(&g_caps.donor_sysres_total, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        g_caps.vam_capable = (g_caps.donor_sysres_total > 0);
    }
    g_hen_sm = hen_sm_proxy;
    g_preopened_nv = INVALID_HANDLE;
    memset(g_mounts, 0, sizeof(g_mounts));
    memset(g_files, 0, sizeof(g_files));
    memset(g_dirs, 0, sizeof(g_dirs));
    memset(g_dlcs, 0, sizeof(g_dlcs));
    g_dlc_count = 0;
    g_has_rom_overlay = false;
    g_rom_overlay_root[0] = '\0';
    g_post_aov_active = 0;
    g_aov_tid = 0;
    g_post_aov_logs = 0;
    g_libnx_heap_used = 0;
    g_game_heap_base = 0;
    g_game_heap_size = 0;
    g_game_heap_cursor = 0;
    g_compat_heap_reserved = 0;
    g_compat_heap_marked = false;
    g_vam_flat_used = 0;
    g_vam_backed_bytes = 0;
    g_std_alloc_init_logs = 0;
    nupSpinInit(&g_handle_lock);

    if (g_nup && g_nup->is_raw && g_nup->raw_root[0]) {
        const char* app_root = g_nup->raw_app_root[0] ? g_nup->raw_app_root : g_nup->raw_root;
        char ov[0x300];
        format_sd_subpath(app_root, "romfs_update", ov, sizeof(ov));
        if (!sd_dir_exists(ov))
            format_sd_subpath(g_nup->raw_root, "romfs_update", ov, sizeof(ov));
        if (sd_dir_exists(ov)) {
            g_has_rom_overlay = true;
            strncpy(g_rom_overlay_root, ov, sizeof(g_rom_overlay_root) - 1);
            nupLogf("[vfs] romfs_update overlay active: %s\n", g_rom_overlay_root);
        }
        char dlc_local[0x300];
        format_sd_subpath(app_root, "dlc", dlc_local, sizeof(dlc_local));
        scan_dlc_parent(dlc_local);
        format_sd_subpath(app_root, "aoc", dlc_local, sizeof(dlc_local));
        scan_dlc_parent(dlc_local);
        if (strcmp(app_root, g_nup->raw_root) != 0) {
            format_sd_subpath(g_nup->raw_root, "dlc", dlc_local, sizeof(dlc_local));
            scan_dlc_parent(dlc_local);
            format_sd_subpath(g_nup->raw_root, "aoc", dlc_local, sizeof(dlc_local));
            scan_dlc_parent(dlc_local);
        }
    } else if (g_nup && !g_nup->is_raw) {
        scan_dlc_in_nup();
    }

    if (g_title_id) {
        char dlc_global[0x300];
        size_t pos = 0;
        dlc_global[0] = '\0';
        append_str(dlc_global, sizeof(dlc_global), &pos, "/kaihen/dlc/");
        append_hex64(dlc_global, sizeof(dlc_global), &pos, g_title_id);
        scan_dlc_parent(dlc_global);
    }

    sort_dlcs();
    if (g_dlc_count > 0) {
        nupLogf("[vfs] discovered %d DLC(s) for tid=%016llx\n",
                g_dlc_count, (unsigned long long)g_title_id);
        for (int i = 0; i < g_dlc_count && i < 8; i++) {
            if (g_dlcs[i].is_nup)
                nupLogf("  dlc[%d] -> NUP dir_idx=%u\n", g_dlcs[i].index, g_dlcs[i].nup_dir_idx);
            else
                nupLogf("  dlc[%d] -> SD %s\n", g_dlcs[i].index, g_dlcs[i].sd_root);
        }
    }
}

// --- Handle & mount lookup ---

static bool is_our_file(void* h, OpenNupFile** out) {
    const uintptr_t p = (uintptr_t)h;
    const uintptr_t lo = (uintptr_t)&g_files[0];
    const uintptr_t hi = (uintptr_t)&g_files[MAX_OPEN_FILES];
    if (p >= lo && p < hi && ((p - lo) % sizeof(OpenNupFile)) == 0) {
        *out = (OpenNupFile*)h;
        return (*out)->in_use;
    }
    return false;
}

static bool is_our_dir(void* h, OpenNupDir** out) {
    const uintptr_t p = (uintptr_t)h;
    const uintptr_t lo = (uintptr_t)&g_dirs[0];
    const uintptr_t hi = (uintptr_t)&g_dirs[MAX_OPEN_DIRS];
    if (p >= lo && p < hi && ((p - lo) % sizeof(OpenNupDir)) == 0) {
        *out = (OpenNupDir*)h;
        return (*out)->in_use;
    }
    return false;
}

static const VfsMount* match_vfs_mount(const char* path, const char** out_rel) {
    if (!path)
        return NULL;
    const char* colon = strchr(path, ':');
    if (!colon)
        return NULL;
    const size_t len = (size_t)(colon - path);
    if (len == 0 || len >= sizeof(g_mounts[0].name))
        return NULL;
    for (int i = 0; i < MAX_VFS_MOUNTS; i++) {
        if (g_mounts[i].kind != MOUNT_NONE &&
            strlen(g_mounts[i].name) == len &&
            memcmp(g_mounts[i].name, path, len) == 0) {
            if (out_rel) *out_rel = colon + 1;
            return &g_mounts[i];
        }
    }
    return NULL;
}

static bool is_mount_name_ours(const char* name) {
    if (!name || !name[0])
        return false;
    for (int i = 0; i < MAX_VFS_MOUNTS; i++) {
        if (g_mounts[i].kind != MOUNT_NONE && strcmp(g_mounts[i].name, name) == 0)
            return true;
    }
    return false;
}

static u32 register_vfs_mount(const char* name, VfsMountKind kind,
                              const char* sd_root, const char* sd_overlay) {
    if (!name || !name[0] || strlen(name) >= sizeof(g_mounts[0].name))
        return NN_FS_INVALID_ARG;
    nupSpinLock(&g_handle_lock);
    int slot = -1;
    for (int i = 0; i < MAX_VFS_MOUNTS; i++) {
        if (g_mounts[i].kind != MOUNT_NONE && strcmp(g_mounts[i].name, name) == 0) {
            slot = i;
            break;
        }
        if (slot < 0 && g_mounts[i].kind == MOUNT_NONE)
            slot = i;
    }
    if (slot < 0) {
        nupSpinUnlock(&g_handle_lock);
        return NN_FS_INVALID_ARG;
    }
    memset(&g_mounts[slot], 0, sizeof(g_mounts[slot]));
    g_mounts[slot].kind = kind;
    strncpy(g_mounts[slot].name, name, sizeof(g_mounts[slot].name) - 1);
    if (sd_root)
        strncpy(g_mounts[slot].sd_root, sd_root, sizeof(g_mounts[slot].sd_root) - 1);
    if (sd_overlay && sd_overlay[0]) {
        g_mounts[slot].has_overlay = true;
        strncpy(g_mounts[slot].sd_overlay, sd_overlay, sizeof(g_mounts[slot].sd_overlay) - 1);
    }
    nupSpinUnlock(&g_handle_lock);
    return 0;
}

static void resolve_mount_sd_path_read(const VfsMount* m, const char* rel,
                                       char* out, size_t out_sz) {
    if (m->has_overlay) {
        format_sd_subpath(m->sd_overlay, rel, out, out_sz);
        u32 et = 0;
        if (R_SUCCEEDED(nupRawFsGetEntryType(g_sd, out, &et)))
            return;
    }
    format_sd_subpath(m->sd_root, rel, out, out_sz);
}

static u32 register_vfs_mount_nup(const char* name, u32 nup_root_dir) {
    if (!name || !name[0] || strlen(name) >= sizeof(g_mounts[0].name))
        return NN_FS_INVALID_ARG;
    nupSpinLock(&g_handle_lock);
    int slot = -1;
    for (int i = 0; i < MAX_VFS_MOUNTS; i++) {
        if (g_mounts[i].kind != MOUNT_NONE && strcmp(g_mounts[i].name, name) == 0) {
            slot = i;
            break;
        }
        if (slot < 0 && g_mounts[i].kind == MOUNT_NONE)
            slot = i;
    }
    if (slot < 0) {
        nupSpinUnlock(&g_handle_lock);
        return NN_FS_INVALID_ARG;
    }
    memset(&g_mounts[slot], 0, sizeof(g_mounts[slot]));
    g_mounts[slot].kind = MOUNT_ROM_NUP;
    g_mounts[slot].nup_root_dir = nup_root_dir;
    strncpy(g_mounts[slot].name, name, sizeof(g_mounts[slot].name) - 1);
    nupSpinUnlock(&g_handle_lock);
    return 0;
}

static u32 register_rom_mount(const char* name) {
    u32 rc;
    if (g_nup && g_nup->is_raw) {
        char rom_root[0x300];
        format_sd_subpath(g_nup->raw_root, "romfs", rom_root, sizeof(rom_root));
        rc = register_vfs_mount(name, MOUNT_SD_RO, rom_root,
                                g_has_rom_overlay ? g_rom_overlay_root : NULL);
    } else {
        rc = register_vfs_mount_nup(name, g_nup ? g_nup->romfs_dir_idx : 0);
    }
    nupLogf("hook MountRom('%s') -> 0x%x\n", name ? name : "(null)", rc);
    return rc;
}

static u32 register_sd_save_mount(const char* tag, const char* name, u64 app_id,
                                  const char* sub, int idx, bool read_only) {
    char root[0x300];
    format_save_root(app_id, sub, idx, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    const u32 rc = register_vfs_mount(name, read_only ? MOUNT_SD_RO : MOUNT_SD_RW, root, NULL);
    nupLogf("hook %s('%s') -> SD '%s' (rc=0x%x)\n",
            tag, name ? name : "(null)", root, rc);
    return rc;
}

// --- Mount / Unmount / Query hooks ---

static u32 hook_QueryMountRomCacheSize1(size_t* out) { if (out) *out = 0x1000; return 0; }
static u32 hook_QueryMountRomCacheSizeAppId(size_t* out, u64 a) { (void)a; if (out) *out = 0x1000; return 0; }
static u32 hook_QueryMountRomCacheSizeIdx(size_t* out, int i) { (void)i; if (out) *out = 0x1000; return 0; }
static u32 hook_MountRom1(const char* name) { return register_rom_mount(name); }
static u32 hook_MountRom3(const char* name, void* b, size_t s) { (void)b; (void)s; return register_rom_mount(name); }
static u32 hook_MountRomAppId(const char* name, u64 a, void* b, size_t s) { (void)a; (void)b; (void)s; return register_rom_mount(name); }
static u32 hook_MountRomIdx(const char* name, int i, void* b, size_t s) { (void)i; (void)b; (void)s; return register_rom_mount(name); }
static bool hook_CanMountRom(u64 app_id) { (void)app_id; return true; }

static u32 hook_Unmount(const char* name) {
    if (name) {
        nupSpinLock(&g_handle_lock);
        for (int i = 0; i < MAX_VFS_MOUNTS; i++) {
            if (g_mounts[i].kind != MOUNT_NONE && strcmp(g_mounts[i].name, name) == 0) {
                g_mounts[i].kind = MOUNT_NONE;
                g_mounts[i].name[0] = '\0';
                nupSpinUnlock(&g_handle_lock);
                nupLogf("hook Unmount('%s') -> OK\n", name);
                return 0;
            }
        }
        nupSpinUnlock(&g_handle_lock);
    }
    return real_Unmount ? real_Unmount(name) : 0;
}

static bool hook_IsMounted(const char* name) {
    if (is_mount_name_ours(name))
        return true;
    return real_IsMounted ? real_IsMounted(name) : false;
}

static bool hook_IsPathMounted(const char* path) {
    if (match_vfs_mount(path, NULL))
        return true;
    return real_IsPathMounted ? real_IsPathMounted(path) : false;
}

// --- Save / Cache / Temp / BCAT SD redirection hooks ---

static u32 hook_MountSaveDataUid(const char* name, const void* uid) {
    (void)uid;
    return register_sd_save_mount("MountSaveData", name, 0, "user", -1, false);
}

static u32 hook_MountSaveDataUserId(const char* name, u64 u0, u64 u1) {
    (void)u0; (void)u1;
    return register_sd_save_mount("MountSaveData(UserId)", name, 0, "user", -1, false);
}

static u32 hook_MountSaveDataAppUid(const char* name, u64 app_id, const void* uid) {
    (void)uid;
    return register_sd_save_mount("MountSaveData(App)", name, app_id, "user", -1, false);
}

static u32 hook_MountSaveDataAppUserId(const char* name, u64 app_id, u64 u0, u64 u1) {
    (void)u0; (void)u1;
    return register_sd_save_mount("MountSaveData(AppUserId)", name, app_id, "user", -1, false);
}

static u32 hook_MountSaveDataReadOnlyUid(const char* name, u64 app_id, const void* uid) {
    (void)uid;
    return register_sd_save_mount("MountSaveDataReadOnly", name, app_id, "user", -1, true);
}

static u32 hook_MountSaveDataReadOnlyUserId(const char* name, u64 app_id, u64 u0, u64 u1) {
    (void)u0; (void)u1;
    return register_sd_save_mount("MountSaveDataReadOnly(UserId)", name, app_id, "user", -1, true);
}

static u32 hook_MountSaveDataForDebug(const char* name) {
    return register_sd_save_mount("MountSaveDataForDebug", name, 0, "user", -1, false);
}

static u32 hook_EnsureSaveData(const void* uid) {
    (void)uid;
    char root[0x300];
    format_save_root(0, "user", -1, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    nupLogf("hook EnsureSaveData() -> SD '%s' OK\n", root);
    return 0;
}

static bool hook_IsSaveDataExistingUid(const void* uid) {
    (void)uid;
    char root[0x300];
    format_save_root(0, "user", -1, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    return true;
}

static bool hook_IsSaveDataExistingAppUid(u64 app_id, const void* uid) {
    (void)uid;
    char root[0x300];
    format_save_root(app_id, "user", -1, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    return true;
}

static u32 hook_IsSaveDataExistingOutUid(bool* out, const void* uid) {
    (void)uid;
    char root[0x300];
    format_save_root(0, "user", -1, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    if (out) *out = true;
    return 0;
}

static u32 hook_IsSaveDataExistingOutAppUid(bool* out, u64 app_id, const void* uid) {
    (void)uid;
    char root[0x300];
    format_save_root(app_id, "user", -1, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    if (out) *out = true;
    return 0;
}

static u32 hook_MountDeviceSaveData1(const char* name) {
    return register_sd_save_mount("MountDeviceSaveData", name, 0, "device", -1, false);
}

static u32 hook_MountDeviceSaveDataApp(const char* name, u64 app_id) {
    return register_sd_save_mount("MountDeviceSaveData(App)", name, app_id, "device", -1, false);
}

static bool hook_IsDeviceSaveDataExisting(u64 app_id) {
    char root[0x300];
    format_save_root(app_id, "device", -1, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    return true;
}

static u32 hook_MountCacheStorage1(const char* name) {
    return register_sd_save_mount("MountCacheStorage", name, 0, "cache", -1, false);
}

static u32 hook_MountCacheStorageIdx(const char* name, int idx) {
    return register_sd_save_mount("MountCacheStorage(Idx)", name, 0, "cache", idx, false);
}

static u32 hook_MountCacheStorageApp(const char* name, u64 app_id) {
    return register_sd_save_mount("MountCacheStorage(App)", name, app_id, "cache", -1, false);
}

static u32 hook_MountCacheStorageAppIdx(const char* name, u64 app_id, int idx) {
    return register_sd_save_mount("MountCacheStorage(AppIdx)", name, app_id, "cache", idx, false);
}

static u32 hook_CreateCacheStorageIdx(int idx, s64 data_sz, s64 journal_sz) {
    (void)data_sz; (void)journal_sz;
    char root[0x300];
    format_save_root(0, "cache", idx, root, sizeof(root));
    ensure_sd_dir_recursive(root);
    nupLogf("hook CreateCacheStorage(idx=%d) -> SD '%s' OK\n", idx, root);
    return 0;
}

static u32 hook_DeleteCacheStorageIdx(int idx) {
    char root[0x300];
    format_save_root(0, "cache", idx, root, sizeof(root));
    if (g_sd) nupRawFsDeleteDirRec(g_sd, root);
    nupLogf("hook DeleteCacheStorage(idx=%d) -> OK\n", idx);
    return 0;
}

static u32 hook_MountTemporaryStorage(const char* name) {
    return register_sd_save_mount("MountTemporaryStorage", name, 0, "temp", -1, false);
}

static u32 hook_MountBcatSaveData(const char* name, u64 app_id) {
    return register_sd_save_mount("MountBcatSaveData", name, app_id, "bcat", -1, false);
}

static u32 hook_ExtendSaveData(const void* uid, s64 data_sz, s64 journal_sz) {
    (void)uid; (void)data_sz; (void)journal_sz;
    return 0;
}

static u32 hook_ExtendDeviceSaveData(s64 data_sz, s64 journal_sz) {
    (void)data_sz; (void)journal_sz;
    return 0;
}

static u32 hook_GetSaveDataSize(s64* out_data, s64* out_journal, const void* uid) {
    (void)uid;
    if (out_data) *out_data = 0x4000000;
    if (out_journal) *out_journal = 0x1000000;
    return 0;
}

static u32 hook_GetSaveDataSizeMax(s64* out_data, s64* out_journal) {
    if (out_data) *out_data = 0x10000000;
    if (out_journal) *out_journal = 0x4000000;
    return 0;
}

static u32 hook_GetDeviceSaveDataSize1(s64* out_data, s64* out_journal) {
    if (out_data) *out_data = 0x4000000;
    if (out_journal) *out_journal = 0x1000000;
    return 0;
}

static u32 hook_GetDeviceSaveDataSizeApp(s64* out_data, s64* out_journal, u64 app_id) {
    (void)app_id;
    if (out_data) *out_data = 0x4000000;
    if (out_journal) *out_journal = 0x1000000;
    return 0;
}

static u32 hook_GetCacheStorageSize(s64* out_data, s64* out_journal, int idx) {
    (void)idx;
    if (out_data) *out_data = 0x4000000;
    if (out_journal) *out_journal = 0x1000000;
    return 0;
}

static u32 hook_GetCacheStorageMax(int* out_idx_max, s64* out_sz_max) {
    if (out_idx_max) *out_idx_max = 16;
    if (out_sz_max) *out_sz_max = 0x10000000;
    return 0;
}

// --- DLC (nn::aoc + nn::fs::MountAddOnContent) SD redirection ---

static int hook_CountAddOnContent(void) {
    nupLogf("hook nn::aoc::CountAddOnContent() -> %d\n", g_dlc_count);
    return g_dlc_count;
}

static int hook_ListAddOnContent(int* out_indices, int offset, int count) {
    int written = 0;
    if (out_indices && offset >= 0 && count > 0) {
        for (int i = offset; i < g_dlc_count && written < count; i++)
            out_indices[written++] = g_dlcs[i].index;
    }
    nupLogf("hook nn::aoc::ListAddOnContent(off=%d, cnt=%d) -> %d\n", offset, count, written);
    return written;
}

static u64 hook_GetAddOnContentBaseId(void) {
    const u64 base_id = (g_title_id & ~0xFFFull) + 0x1000ull;
    nupLogf("hook nn::aoc::GetAddOnContentBaseId() -> %016llx\n", (unsigned long long)base_id);
    return base_id;
}

static void hook_AocNoopVoid(void) {}
static u32 hook_AocOkU32(void) { return 0; }
static void hook_PrepareAddOnContent(int idx) { (void)idx; }
static void hook_NotifyAocDataId(u64 data_id) { (void)data_id; }

static u32 hook_QueryMountAddOnContentCacheSize(size_t* out, int idx) {
    (void)idx;
    if (out) *out = 0x1000;
    return 0;
}

static u32 hook_MountAddOnContent(const char* name, int idx, void* cache, size_t cache_sz) {
    (void)cache; (void)cache_sz;
    for (int i = 0; i < g_dlc_count; i++) {
        if (g_dlcs[i].index == idx) {
            u32 rc;
            if (g_dlcs[i].is_nup) {
                rc = register_vfs_mount_nup(name, g_dlcs[i].nup_dir_idx);
                nupLogf("hook MountAddOnContent('%s', idx=%d) -> NUP dir=%u (rc=0x%x)\n",
                        name ? name : "(null)", idx, g_dlcs[i].nup_dir_idx, rc);
            } else {
                rc = register_vfs_mount(name, MOUNT_SD_RO, g_dlcs[i].sd_root, NULL);
                nupLogf("hook MountAddOnContent('%s', idx=%d) -> SD '%s' (rc=0x%x)\n",
                        name ? name : "(null)", idx, g_dlcs[i].sd_root, rc);
            }
            return rc;
        }
    }
    nupLogf("hook MountAddOnContent('%s', idx=%d) -> NOT FOUND\n", name ? name : "(null)", idx);
    return NN_FS_PATH_NOT_FOUND;
}

// --- File & Directory I/O hooks ---

static bool ends_with_zst(const char* s) {
    const size_t n = s ? strlen(s) : 0;
    return n >= 4 && memcmp(s + n - 4, ".zst", 4) == 0;
}

static Result raw_file_read_loop(FsFile* f, s64 off, void* dst, size_t sz, size_t* out_read) {
    if (out_read) *out_read = 0;
    if (off < 0) return NN_FS_INVALID_ARG;
    u64 total = 0;
    Result rc = 0;
    while (total < sz) {
        u64 chunk = (sz - total) > 0x400000 ? 0x400000 : (sz - total);
        u64 got = 0;
        rc = nupRawFileRead(f, off + (s64)total, (u8*)dst + total, chunk, &got);
        if (R_FAILED(rc)) break;
        total += got;
        if (got < chunk) break;
    }
    if (out_read) *out_read = (size_t)total;
    return rc;
}

static Result raw_file_write_loop(FsFile* f, s64 off, const void* src, size_t sz, u32 opt) {
    if (off < 0) return NN_FS_INVALID_ARG;
    if (sz == 0) {
        if (opt & FsWriteOption_Flush)
            return nupRawFileFlush(f);
        return 0;
    }
    u64 total = 0;
    while (total < sz) {
        u64 chunk = (sz - total) > 0x400000 ? 0x400000 : (sz - total);
        const u32 chunk_opt = (total + chunk >= sz) ? opt : FsWriteOption_None;
        Result rc = nupRawFileWrite(f, off + (s64)total, (const u8*)src + total, chunk, chunk_opt);
        if (R_FAILED(rc)) return rc;
        total += chunk;
    }
    return 0;
}

static bool lookup_nup_mount(const VfsMount* m, const char* rel, bool* out_is_dir, u32* out_idx) {
    if (m->nup_root_dir == g_nup->romfs_dir_idx && g_nup->romfs_layer_count > 1)
        return nupLookupRomfs(g_nup, rel, out_is_dir, out_idx);
    return nupLookupInDir(g_nup, m->nup_root_dir, rel, out_is_dir, out_idx);
}

static u32 g_total_open_logs = 0;

static u32 hook_GetEntryType(u32* out_type, const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m) {
        u32 rc = real_GetEntryType ? real_GetEntryType(out_type, path) : NN_FS_PATH_NOT_FOUND;
        if (g_entry_type_logs < 15) {
            g_entry_type_logs++;
            nupLogf("hook GetEntryType(real '%s') -> 0x%x\n", path ? path : "(null)", rc);
        }
        return rc;
    }
    if (m->kind == MOUNT_SD_RO || m->kind == MOUNT_SD_RW) {
        char sd_path[FS_MAX_PATH];
        resolve_mount_sd_path_read(m, rel, sd_path, sizeof(sd_path));
        u32 et = 0;
        Result rc = nupRawFsGetEntryType(g_sd, sd_path, &et);
        if (R_FAILED(rc)) {
            if (!ends_with_zst(path) && g_entry_type_fail_logs < 32) {
                g_entry_type_fail_logs++;
                nupLogf("hook GetEntryType(%s '%s' -> '%s') -> FAILED 0x%x\n",
                        m->kind == MOUNT_SD_RW ? "rw" : "raw",
                        path ? path : "(null)", sd_path, rc);
            }
            return rc;
        }
        if (out_type) *out_type = et;
        return 0;
    }
    bool is_dir = false;
    u32 idx = 0;
    if (!lookup_nup_mount(m, rel, &is_dir, &idx)) {
        if (!ends_with_zst(path) && g_entry_type_fail_logs < 32) {
            g_entry_type_fail_logs++;
            nupLogf("hook GetEntryType(rom '%s') -> NOT FOUND\n", path ? path : "(null)");
        }
        return NN_FS_PATH_NOT_FOUND;
    }
    if (out_type)
        *out_type = is_dir ? 0 : 1;
    return 0;
}

static u32 hook_OpenFile(NnFileHandle* out, const char* path, int mode) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m) {
        u32 rc = real_OpenFile ? real_OpenFile(out, path, mode) : NN_FS_PATH_NOT_FOUND;
        nupLogf("hook OpenFile(real '%s', mode=%d) -> 0x%x\n", path ? path : "(null)", mode, rc);
        return rc;
    }
    if (m->kind == MOUNT_SD_RO || m->kind == MOUNT_SD_RW) {
        if (m->kind == MOUNT_SD_RO && (mode & (FsOpenMode_Write | FsOpenMode_Append)))
            return NN_FS_UNSUPPORTED_OPERATION;
        char sd_path[FS_MAX_PATH];
        if (m->kind == MOUNT_SD_RO)
            resolve_mount_sd_path_read(m, rel, sd_path, sizeof(sd_path));
        else
            format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
        const u32 open_mode = (m->kind == MOUNT_SD_RW)
            ? ((u32)mode & (FsOpenMode_Read | FsOpenMode_Write | FsOpenMode_Append))
            : FsOpenMode_Read;
        FsFile rf = {};
        Result rc = nupRawFsOpenFile(g_sd, sd_path, open_mode ? open_mode : FsOpenMode_Read, &rf);
        if (R_FAILED(rc)) {
            if (!ends_with_zst(path))
                nupLogf("hook OpenFile(%s '%s', mode=%d) -> 0x%x\n",
                        m->kind == MOUNT_SD_RW ? "rw" : "raw", path, mode, rc);
            return rc;
        }
        s64 rsz = 0;
        nupRawFileGetSize(&rf, &rsz);
        nupSpinLock(&g_handle_lock);
        for (int i = 0; i < MAX_OPEN_FILES; i++) {
            if (!g_files[i].in_use) {
                g_files[i].in_use = true;
                g_files[i].is_raw = true;
                g_files[i].is_rw = (m->kind == MOUNT_SD_RW);
                g_files[i].open_mode = mode;
                g_files[i].raw_file = rf;
                g_files[i].raw_size = rsz;
                out->handle = &g_files[i];
                const u32 cnt = ++g_open_file_count;
                const u32 tot = ++g_total_open_logs;
                nupSpinUnlock(&g_handle_lock);
                if (m->kind == MOUNT_SD_RW) {
                    nupLogf("hook OpenFile #%u(rw '%s', mode=%d) -> OK (size=%lld)\n",
                            tot, path, mode, (long long)rsz);
                } else if (tot <= 32 || (tot % 250) == 0) {
                    nupLogBufferedf("hook OpenFile #%u(raw '%s', open=%u) -> OK (size=%lld)\n",
                                    tot, path, cnt, (long long)rsz);
                }
                return 0;
            }
        }
        nupSpinUnlock(&g_handle_lock);
        serviceClose(&rf.s);
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    }
    if (mode & (FsOpenMode_Write | FsOpenMode_Append))
        return NN_FS_UNSUPPORTED_OPERATION;
    bool is_dir = false;
    u32 idx = 0;
    if (!lookup_nup_mount(m, rel, &is_dir, &idx) || is_dir) {
        if (!ends_with_zst(path))
            nupLogf("hook OpenFile(rom '%s') -> NOT FOUND\n", path);
        return NN_FS_PATH_NOT_FOUND;
    }
    nupSpinLock(&g_handle_lock);
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (!g_files[i].in_use) {
            g_files[i].in_use = true;
            g_files[i].is_raw = false;
            g_files[i].is_rw = false;
            g_files[i].open_mode = mode;
            g_files[i].file_idx = idx;
            out->handle = &g_files[i];
            const u32 cnt = ++g_open_file_count;
            const u32 tot = ++g_total_open_logs;
            nupSpinUnlock(&g_handle_lock);
            if (tot <= 32 || (tot % 250) == 0) {
                nupLogBufferedf("hook OpenFile #%u(rom '%s', open=%u) -> OK (size=%llu)\n",
                                tot, path, cnt, (unsigned long long)g_nup->files[idx].size);
            }
            return 0;
        }
    }
    nupSpinUnlock(&g_handle_lock);
    nupLogf("hook OpenFile(rom '%s') -> TOO MANY OPEN FILES\n", path);
    return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
}

static u32 hook_ReadFileAtOnce(const char* path, void* dst, size_t sz) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_ReadFileAtOnce ? real_ReadFileAtOnce(path, dst, sz) : NN_FS_PATH_NOT_FOUND;
    if (m->kind == MOUNT_SD_RO || m->kind == MOUNT_SD_RW) {
        char sd_path[FS_MAX_PATH];
        resolve_mount_sd_path_read(m, rel, sd_path, sizeof(sd_path));
        FsFile rf = {};
        Result rc = nupRawFsOpenFile(g_sd, sd_path, FsOpenMode_Read, &rf);
        if (R_FAILED(rc))
            return rc;
        size_t got = 0;
        rc = raw_file_read_loop(&rf, 0, dst, sz, &got);
        serviceClose(&rf.s);
        return rc;
    }
    bool is_dir = false;
    u32 idx = 0;
    if (!lookup_nup_mount(m, rel, &is_dir, &idx) || is_dir)
        return NN_FS_PATH_NOT_FOUND;
    size_t got = 0;
    return nupReadFile(g_nup, idx, 0, dst, sz, &got);
}

static void trace_read_begin(const OpenNupFile* f, u64 tid, u64 caller, s64 off, size_t sz,
                             char* name_out, size_t name_sz, bool* is_aov_out) {
    (void)f; (void)tid; (void)caller; (void)off; (void)sz; (void)name_sz;
    name_out[0] = '\0';
    *is_aov_out = false;
}

static void trace_read_result(const char* tag, u64 tid, u64 caller, const char* name, bool is_aov,
                              s64 off, const void* dst, size_t sz, size_t got, u32 rc) {
    if (is_aov || R_FAILED(rc)) {
        nupLogBufferedf("[io<] tid=%llu caller=0x%llx %s rc=0x%x got=0x%zx\n",
                        (unsigned long long)tid, (unsigned long long)caller,
                        (name && name[0]) ? name : tag, rc, got);
    } else if (g_read_file_logs < 8) {
        g_read_file_logs++;
        u32 magic = 0;
        if (R_SUCCEEDED(rc) && dst && got >= 4)
            memcpy(&magic, dst, 4);
        nupLogBufferedf("hook %s(off=0x%llx, sz=0x%zx) -> rc=0x%x got=0x%zx magic=%08x\n",
                        tag, (unsigned long long)off, sz, rc, got, magic);
    }
}

static u32 hook_ReadFile6(size_t* out_size, NnFileHandle h, s64 off, void* dst, size_t sz, const void* opt) {
    (void)opt;
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_ReadFile6 ? real_ReadFile6(out_size, h, off, dst, sz, opt) : NN_FS_INVALID_ARG;
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    char fname[64];
    bool is_aov = false;
    trace_read_begin(f, tid, caller, off, sz, fname, sizeof(fname), &is_aov);
    size_t got = 0;
    u32 rc = f->is_raw ? raw_file_read_loop(&f->raw_file, off, dst, sz, &got)
                       : nupReadFile(g_nup, f->file_idx, off, dst, sz, &got);
    if (out_size) *out_size = got;
    trace_read_result("ReadFile6", tid, caller, fname, is_aov, off, dst, sz, got, rc);
    return rc;
}

static u32 hook_ReadFile5Out(size_t* out_size, NnFileHandle h, s64 off, void* dst, size_t sz) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_ReadFile5Out ? real_ReadFile5Out(out_size, h, off, dst, sz) : NN_FS_INVALID_ARG;
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    char fname[64];
    bool is_aov = false;
    trace_read_begin(f, tid, caller, off, sz, fname, sizeof(fname), &is_aov);
    size_t got = 0;
    u32 rc = f->is_raw ? raw_file_read_loop(&f->raw_file, off, dst, sz, &got)
                       : nupReadFile(g_nup, f->file_idx, off, dst, sz, &got);
    if (out_size) *out_size = got;
    trace_read_result("ReadFile5Out", tid, caller, fname, is_aov, off, dst, sz, got, rc);
    return rc;
}

static u32 hook_ReadFile5Opt(NnFileHandle h, s64 off, void* dst, size_t sz, const void* opt) {
    (void)opt;
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_ReadFile5Opt ? real_ReadFile5Opt(h, off, dst, sz, opt) : NN_FS_INVALID_ARG;
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    char fname[64];
    bool is_aov = false;
    trace_read_begin(f, tid, caller, off, sz, fname, sizeof(fname), &is_aov);
    size_t got = 0;
    u32 rc = f->is_raw ? raw_file_read_loop(&f->raw_file, off, dst, sz, &got)
                       : nupReadFile(g_nup, f->file_idx, off, dst, sz, &got);
    trace_read_result("ReadFile5Opt", tid, caller, fname, is_aov, off, dst, sz, got, rc);
    return rc;
}

static u32 hook_ReadFile4(NnFileHandle h, s64 off, void* dst, size_t sz) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_ReadFile4 ? real_ReadFile4(h, off, dst, sz) : NN_FS_INVALID_ARG;
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    char fname[64];
    bool is_aov = false;
    trace_read_begin(f, tid, caller, off, sz, fname, sizeof(fname), &is_aov);
    size_t got = 0;
    u32 rc = f->is_raw ? raw_file_read_loop(&f->raw_file, off, dst, sz, &got)
                       : nupReadFile(g_nup, f->file_idx, off, dst, sz, &got);
    trace_read_result("ReadFile4", tid, caller, fname, is_aov, off, dst, sz, got, rc);
    return rc;
}

static u32 hook_WriteFile(NnFileHandle h, s64 off, const void* src, size_t sz, const void* opt) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_WriteFile ? real_WriteFile(h, off, src, sz, opt) : NN_FS_INVALID_ARG;
    if (!f->is_raw || !f->is_rw)
        return NN_FS_UNSUPPORTED_OPERATION;
    const u32 wopt = opt ? (*(const u32*)opt) : FsWriteOption_None;
    return raw_file_write_loop(&f->raw_file, off, src, sz, wopt);
}

static u32 hook_FlushFile(NnFileHandle h) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_FlushFile ? real_FlushFile(h) : NN_FS_INVALID_ARG;
    if (!f->is_raw || !f->is_rw)
        return 0;
    return nupRawFileFlush(&f->raw_file);
}

static u32 hook_SetFileSize(NnFileHandle h, s64 size) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_SetFileSize ? real_SetFileSize(h, size) : NN_FS_INVALID_ARG;
    if (!f->is_raw || !f->is_rw)
        return NN_FS_UNSUPPORTED_OPERATION;
    Result rc = nupRawFileSetSize(&f->raw_file, size);
    if (R_SUCCEEDED(rc))
        f->raw_size = size;
    return rc;
}

static u32 hook_GetFileSize(s64* out_size, NnFileHandle h) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_GetFileSize ? real_GetFileSize(out_size, h) : NN_FS_INVALID_ARG;
    if (f->is_raw && f->is_rw) {
        s64 sz = 0;
        Result rc = nupRawFileGetSize(&f->raw_file, &sz);
        if (R_SUCCEEDED(rc) && out_size)
            *out_size = sz;
        return rc;
    }
    if (out_size)
        *out_size = f->is_raw ? f->raw_size : (s64)g_nup->files[f->file_idx].size;
    return 0;
}

static int hook_GetFileOpenMode(NnFileHandle h) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f))
        return real_GetFileOpenMode ? real_GetFileOpenMode(h) : 0;
    return f->open_mode;
}

static void hook_CloseFile(NnFileHandle h) {
    OpenNupFile* f = NULL;
    if (!is_our_file(h.handle, &f)) {
        if (real_CloseFile) real_CloseFile(h);
        return;
    }
    FsFile to_close = {};
    bool do_close = false;
    nupSpinLock(&g_handle_lock);
    if (f->is_raw) {
        to_close = f->raw_file;
        do_close = true;
    }
    f->in_use = false;
    nupSpinUnlock(&g_handle_lock);
    if (g_open_file_count > 0)
        __atomic_fetch_sub(&g_open_file_count, 1, __ATOMIC_RELAXED);
    if (do_close)
        serviceClose(&to_close.s);
}

static u32 hook_CreateFile3(const char* path, s64 size, int option) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_CreateFile3 ? real_CreateFile3(path, size, option) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    Result rc = nupRawFsCreateFile(g_sd, sd_path, size, (u32)option);
    nupLogf("hook CreateFile('%s', size=%lld) -> 0x%x\n", path, (long long)size, rc);
    return rc;
}

static u32 hook_CreateFile2(const char* path, s64 size) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_CreateFile2 ? real_CreateFile2(path, size) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    Result rc = nupRawFsCreateFile(g_sd, sd_path, size, 0);
    nupLogf("hook CreateFile('%s', size=%lld) -> 0x%x\n", path, (long long)size, rc);
    return rc;
}

static u32 hook_CreateAndWriteFileAtOnce(const char* path, const void* src, size_t sz) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_CreateAndWriteFileAtOnce ? real_CreateAndWriteFileAtOnce(path, src, sz) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    Result rc = nupRawFsCreateFile(g_sd, sd_path, (s64)sz, 0);
    if (R_FAILED(rc))
        return rc;
    FsFile rf = {};
    rc = nupRawFsOpenFile(g_sd, sd_path, FsOpenMode_Write, &rf);
    if (R_FAILED(rc))
        return rc;
    rc = raw_file_write_loop(&rf, 0, src, sz, FsWriteOption_Flush);
    serviceClose(&rf.s);
    return rc;
}

static u32 hook_DeleteFile(const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_DeleteFile ? real_DeleteFile(path) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    return nupRawFsDeleteFile(g_sd, sd_path);
}

static u32 hook_RenameFile(const char* cur_path, const char* new_path) {
    const char* rel1 = NULL;
    const char* rel2 = NULL;
    const VfsMount* m1 = match_vfs_mount(cur_path, &rel1);
    const VfsMount* m2 = match_vfs_mount(new_path, &rel2);
    if (!m1 && !m2)
        return real_RenameFile ? real_RenameFile(cur_path, new_path) : NN_FS_PATH_NOT_FOUND;
    if (!m1 || !m2 || m1->kind != MOUNT_SD_RW || m2->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char p1[FS_MAX_PATH], p2[FS_MAX_PATH];
    format_sd_subpath(m1->sd_root, rel1, p1, sizeof(p1));
    format_sd_subpath(m2->sd_root, rel2, p2, sizeof(p2));
    return nupRawFsRenameFile(g_sd, p1, p2);
}

static u32 hook_CreateDirectory(const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_CreateDirectory ? real_CreateDirectory(path) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    return nupRawFsCreateDir(g_sd, sd_path);
}

static u32 hook_DeleteDirectory(const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_DeleteDirectory ? real_DeleteDirectory(path) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    return nupRawFsDeleteDir(g_sd, sd_path);
}

static u32 hook_DeleteDirectoryRec(const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_DeleteDirectoryRec ? real_DeleteDirectoryRec(path) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    return nupRawFsDeleteDirRec(g_sd, sd_path);
}

static u32 hook_CleanDirectoryRec(const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_CleanDirectoryRec ? real_CleanDirectoryRec(path) : NN_FS_PATH_NOT_FOUND;
    if (m->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char sd_path[FS_MAX_PATH];
    format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
    return nupRawFsCleanDirRec(g_sd, sd_path);
}

static u32 hook_RenameDirectory(const char* cur_path, const char* new_path) {
    const char* rel1 = NULL;
    const char* rel2 = NULL;
    const VfsMount* m1 = match_vfs_mount(cur_path, &rel1);
    const VfsMount* m2 = match_vfs_mount(new_path, &rel2);
    if (!m1 && !m2)
        return real_RenameDirectory ? real_RenameDirectory(cur_path, new_path) : NN_FS_PATH_NOT_FOUND;
    if (!m1 || !m2 || m1->kind != MOUNT_SD_RW || m2->kind != MOUNT_SD_RW)
        return NN_FS_UNSUPPORTED_OPERATION;
    char p1[FS_MAX_PATH], p2[FS_MAX_PATH];
    format_sd_subpath(m1->sd_root, rel1, p1, sizeof(p1));
    format_sd_subpath(m2->sd_root, rel2, p2, sizeof(p2));
    return nupRawFsRenameDir(g_sd, p1, p2);
}

static u32 hook_GetFreeSpaceSize(s64* out_size, const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_GetFreeSpaceSize ? real_GetFreeSpaceSize(out_size, path) : NN_FS_PATH_NOT_FOUND;
    if (m->kind == MOUNT_SD_RW) {
        char sd_path[FS_MAX_PATH];
        format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
        return nupRawFsGetFreeSpace(g_sd, sd_path, out_size);
    }
    if (out_size) *out_size = 0;
    return 0;
}

static u32 hook_GetTotalSpaceSize(s64* out_size, const char* path) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m)
        return real_GetTotalSpaceSize ? real_GetTotalSpaceSize(out_size, path) : NN_FS_PATH_NOT_FOUND;
    if (m->kind == MOUNT_SD_RW) {
        char sd_path[FS_MAX_PATH];
        format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
        return nupRawFsGetTotalSpace(g_sd, sd_path, out_size);
    }
    if (out_size) *out_size = 0;
    return 0;
}

static u32 hook_Commit1(const char* name) {
    if (is_mount_name_ours(name)) {
        if (g_sd) nupRawFsCommit(g_sd);
        nupLogf("hook Commit('%s') -> SD OK\n", name);
        return 0;
    }
    return real_Commit1 ? real_Commit1(name) : 0;
}

static u32 hook_Commit2(const char* name, const void* opt) {
    if (is_mount_name_ours(name)) {
        if (g_sd) nupRawFsCommit(g_sd);
        nupLogf("hook Commit('%s', opt) -> SD OK\n", name);
        return 0;
    }
    return real_Commit2 ? real_Commit2(name, opt) : 0;
}

static u32 hook_CommitMulti(const char* const* names, int count) {
    bool any_ours = false;
    bool any_real = false;
    for (int i = 0; i < count; i++) {
        if (names && is_mount_name_ours(names[i])) any_ours = true;
        else any_real = true;
    }
    if (any_ours && g_sd)
        nupRawFsCommit(g_sd);
    if (any_real && real_CommitMulti)
        return real_CommitMulti(names, count);
    return 0;
}

static u32 hook_CommitSaveData(const char* name) {
    if (is_mount_name_ours(name)) {
        if (g_sd) nupRawFsCommit(g_sd);
        nupLogf("hook CommitSaveData('%s') -> SD OK\n", name);
        return 0;
    }
    return real_CommitSaveData ? real_CommitSaveData(name) : 0;
}

static u32 collect_nup_mount_dirs(const VfsMount* m, const char* rel,
                                  u32 out_idxs[NUP_MAX_ROMFS_LAYERS]) {
    if (m->nup_root_dir == g_nup->romfs_dir_idx && g_nup->romfs_layer_count > 1) {
        u32 n = 0;
        for (u32 l = 0; l < g_nup->romfs_layer_count; l++) {
            bool is_dir = false;
            u32 idx = 0;
            if (nupLookupInDir(g_nup, g_nup->romfs_dirs[l], rel, &is_dir, &idx)) {
                if (!is_dir)
                    return n; // shadowed by a file in this layer
                bool dup = false;
                for (u32 k = 0; k < n; k++) {
                    if (out_idxs[k] == idx) { dup = true; break; }
                }
                if (!dup && n < NUP_MAX_ROMFS_LAYERS)
                    out_idxs[n++] = idx;
            }
        }
        return n;
    }
    bool is_dir = false;
    u32 idx = 0;
    if (nupLookupInDir(g_nup, m->nup_root_dir, rel, &is_dir, &idx) && is_dir) {
        out_idxs[0] = idx;
        return 1;
    }
    return 0;
}

static bool nup_child_info(u32 node, const char** out_name, u32* out_len,
                           bool* out_is_dir, u64* out_size) {
    if (node < g_nup->dir_count) {
        const NupDirEntry* cd = &g_nup->dirs[node];
        *out_name = g_nup->strings + cd->name_off;
        *out_len = cd->name_len;
        *out_is_dir = true;
        *out_size = 0;
        return true;
    }
    if (node < g_nup->dir_count + g_nup->file_count) {
        const NupFileEntry* cf = &g_nup->files[node - g_nup->dir_count];
        *out_name = g_nup->strings + cf->name_off;
        *out_len = cf->name_len;
        *out_is_dir = false;
        *out_size = cf->size;
        return true;
    }
    return false;
}

static bool nup_entry_shadowed(const OpenNupDir* dir, u32 layer_pos,
                               const char* name, u32 name_len) {
    for (u32 prev = 0; prev < layer_pos; prev++) {
        const NupDirEntry* pd = &g_nup->dirs[dir->dir_idxs[prev]];
        for (u32 i = 0; i < pd->child_count; i++) {
            const char* pname = NULL;
            u32 plen = 0;
            bool pdir = false;
            u64 psz = 0;
            if (nup_child_info(g_nup->children[pd->first_child + i], &pname, &plen, &pdir, &psz) &&
                plen == name_len && memcmp(pname, name, name_len) == 0)
                return true;
        }
    }
    return false;
}

static u32 hook_OpenDirectory(NnDirHandle* out, const char* path, int mode) {
    const char* rel = NULL;
    const VfsMount* m = match_vfs_mount(path, &rel);
    if (!m) {
        u32 rc = real_OpenDirectory ? real_OpenDirectory(out, path, mode) : NN_FS_PATH_NOT_FOUND;
        nupLogf("hook OpenDirectory(real '%s') -> 0x%x\n", path ? path : "(null)", rc);
        return rc;
    }
    if (m->kind == MOUNT_SD_RO || m->kind == MOUNT_SD_RW) {
        char sd_path[FS_MAX_PATH];
        if (m->kind == MOUNT_SD_RO)
            resolve_mount_sd_path_read(m, rel, sd_path, sizeof(sd_path));
        else
            format_sd_subpath(m->sd_root, rel, sd_path, sizeof(sd_path));
        FsDir rd = {};
        Result rc = nupRawFsOpenDir(g_sd, sd_path, (u32)mode, &rd);
        if (R_FAILED(rc)) {
            nupLogf("hook OpenDirectory(sd '%s') -> 0x%x\n", path, rc);
            return rc;
        }
        nupSpinLock(&g_handle_lock);
        for (int i = 0; i < MAX_OPEN_DIRS; i++) {
            if (!g_dirs[i].in_use) {
                g_dirs[i].in_use = true;
                g_dirs[i].is_raw = true;
                g_dirs[i].raw_dir = rd;
                out->handle = &g_dirs[i];
                nupSpinUnlock(&g_handle_lock);
                if (g_open_dir_logs < 40) {
                    g_open_dir_logs++;
                    nupLogf("hook OpenDirectory(sd '%s') -> OK\n", path);
                }
                return 0;
            }
        }
        nupSpinUnlock(&g_handle_lock);
        serviceClose(&rd.s);
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    }
    u32 dir_idxs[NUP_MAX_ROMFS_LAYERS];
    const u32 dir_cnt = collect_nup_mount_dirs(m, rel, dir_idxs);
    if (dir_cnt == 0) {
        nupLogf("hook OpenDirectory(rom '%s') -> NOT FOUND\n", path);
        return NN_FS_PATH_NOT_FOUND;
    }
    nupSpinLock(&g_handle_lock);
    for (int i = 0; i < MAX_OPEN_DIRS; i++) {
        if (!g_dirs[i].in_use) {
            g_dirs[i].in_use = true;
            g_dirs[i].is_raw = false;
            g_dirs[i].eof_logged = false;
            memcpy(g_dirs[i].dir_idxs, dir_idxs, dir_cnt * sizeof(u32));
            g_dirs[i].dir_count = dir_cnt;
            g_dirs[i].layer_pos = 0;
            g_dirs[i].cursor = 0;
            g_dirs[i].mode = mode;
            out->handle = &g_dirs[i];
            nupSpinUnlock(&g_handle_lock);
            if (g_open_dir_logs < 40) {
                g_open_dir_logs++;
                nupLogf("hook OpenDirectory(rom '%s', layers=%u) -> OK\n", path, dir_cnt);
            }
            return 0;
        }
    }
    nupSpinUnlock(&g_handle_lock);
    return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
}

static u32 hook_ReadDirectory(s64* out_count, NnDirectoryEntry* out_buf, NnDirHandle h, s64 max_count) {
    OpenNupDir* dir = NULL;
    if (!is_our_dir(h.handle, &dir))
        return real_ReadDirectory ? real_ReadDirectory(out_count, out_buf, h, max_count) : NN_FS_INVALID_ARG;
    if (dir->is_raw) {
        s64 got = 0;
        Result rc = nupRawDirRead(&dir->raw_dir, &got, (FsDirectoryEntry*)out_buf, (u64)max_count);
        if (out_count) *out_count = R_SUCCEEDED(rc) ? got : 0;
        return rc;
    }
    s64 written = 0;
    while (written < max_count && dir->layer_pos < dir->dir_count) {
        const NupDirEntry* d = &g_nup->dirs[dir->dir_idxs[dir->layer_pos]];
        if (dir->cursor >= d->child_count) {
            dir->layer_pos++;
            dir->cursor = 0;
            continue;
        }
        const u32 node = g_nup->children[d->first_child + dir->cursor++];
        const char* cname = NULL;
        u32 clen = 0;
        bool cdir = false;
        u64 csize = 0;
        if (!nup_child_info(node, &cname, &clen, &cdir, &csize))
            continue;
        if (nup_entry_shadowed(dir, dir->layer_pos, cname, clen))
            continue;
        if (cdir) {
            if (!(dir->mode & 1)) continue;
            memset(&out_buf[written], 0, sizeof(out_buf[written]));
            const size_t n = clen < 0x300 ? clen : 0x300;
            memcpy(out_buf[written].name, cname, n);
            out_buf[written].type = 0;
            written++;
        } else {
            if (!(dir->mode & 2)) continue;
            memset(&out_buf[written], 0, sizeof(out_buf[written]));
            const size_t n = clen < 0x300 ? clen : 0x300;
            memcpy(out_buf[written].name, cname, n);
            out_buf[written].type = 1;
            out_buf[written].file_size = (s64)csize;
            written++;
        }
    }
    while (dir->layer_pos < dir->dir_count &&
           dir->cursor >= g_nup->dirs[dir->dir_idxs[dir->layer_pos]].child_count) {
        dir->layer_pos++;
        dir->cursor = 0;
    }
    if (out_count) *out_count = written;
    return 0;
}

static u32 hook_GetDirEntryCount(s64* out_count, NnDirHandle h) {
    OpenNupDir* dir = NULL;
    if (!is_our_dir(h.handle, &dir))
        return real_GetDirEntryCount ? real_GetDirEntryCount(out_count, h) : NN_FS_INVALID_ARG;
    if (dir->is_raw) {
        s64 cnt = 0;
        Result rc = nupRawDirGetEntryCount(&dir->raw_dir, &cnt);
        if (out_count) *out_count = R_SUCCEEDED(rc) ? cnt : 0;
        return rc;
    }
    s64 cnt = 0;
    for (u32 lp = 0; lp < dir->dir_count; lp++) {
        const NupDirEntry* d = &g_nup->dirs[dir->dir_idxs[lp]];
        for (u32 i = 0; i < d->child_count; i++) {
            const char* cname = NULL;
            u32 clen = 0;
            bool cdir = false;
            u64 csize = 0;
            if (!nup_child_info(g_nup->children[d->first_child + i], &cname, &clen, &cdir, &csize))
                continue;
            if (nup_entry_shadowed(dir, lp, cname, clen))
                continue;
            if (cdir) { if (dir->mode & 1) cnt++; }
            else { if (dir->mode & 2) cnt++; }
        }
    }
    if (out_count) *out_count = cnt;
    return 0;
}

static void hook_CloseDirectory(NnDirHandle h) {
    OpenNupDir* dir = NULL;
    if (!is_our_dir(h.handle, &dir)) {
        if (real_CloseDirectory) real_CloseDirectory(h);
        return;
    }
    FsDir to_close = {};
    bool do_close = false;
    nupSpinLock(&g_handle_lock);
    if (dir->is_raw) {
        to_close = dir->raw_dir;
        do_close = true;
    }
    dir->in_use = false;
    nupSpinUnlock(&g_handle_lock);
    if (do_close)
        serviceClose(&to_close.s);
}

// --- Service Manager & Memory hooks ---

static u32 hook_GetServiceHandle(u32* out_handle, const char* name, size_t name_len) {
    char buf[9] = {};
    if (name && name_len && name_len <= 8)
        memcpy(buf, name, name_len);
    if (strcmp(buf, "nvdrv") == 0 && g_preopened_nv != INVALID_HANDLE) {
        Handle h = g_preopened_nv;
        g_preopened_nv = INVALID_HANDLE;
        nupLogf("hook GetServiceHandle('nvdrv') -> GSV delegated nvservices OK (h=0x%x)\n", h);
        if (out_handle) *out_handle = h;
        return 0;
    }
    u32 rc = real_GetServiceHandle ? real_GetServiceHandle(out_handle, name, name_len)
                                   : MAKERESULT(Module_Libnx, LibnxError_NotFound);
    if (R_SUCCEEDED(rc)) {
        nupLogf("hook GetServiceHandle('%s') -> OK\n", buf);
        return rc;
    }
    const bool acl_denied = (rc == 0x1015u); // sm::ResultNotAllowed (Module 21, Desc 8)
    const char* rc_tag = acl_denied ? "ACL_DENIED" : "ERR";
    if (g_hen_sm == INVALID_HANDLE || !buf[0]) {
        nupLogf("hook GetServiceHandle('%s') -> FAILED %s(0x%x) [no HEN proxy]\n", buf, rc_tag, rc);
        return rc;
    }
    nupLogf("hook GetServiceHandle('%s') %s(0x%x) -> trying HEN proxy...\n", buf, rc_tag, rc);
    const SmServiceName encoded = smEncodeName(buf);
    Service proxy = {};
    serviceCreate(&proxy, g_hen_sm);
    proxy.own_handle = 0;
    Handle h = INVALID_HANDLE;
    const Result proxy_rc = serviceDispatchIn(&proxy, 1, encoded,
        .out_handle_attrs = {SfOutHandleAttr_HipcMove},
        .out_handles = &h);
    if (R_SUCCEEDED(proxy_rc) && h != INVALID_HANDLE) {
        nupLogf("hook GetServiceHandle('%s') -> HEN proxy OK (bypassed %s)\n", buf, rc_tag);
        if (out_handle) *out_handle = h;
        return 0;
    }
    nupLogf("hook GetServiceHandle('%s') -> FAILED %s(0x%x) proxy=0x%x\n", buf, rc_tag, rc, proxy_rc);
    return rc;
}

static u32 hook_SetMemoryHeapSize(size_t size) {
    if (!g_libnx_heap_used) {
        u64 heap_region_base = 0;
        svcGetInfo(&heap_region_base, InfoType_HeapRegionAddress, CUR_PROCESS_HANDLE, 0);
        u64 reserved_end = heap_region_base;
        u64 addr = heap_region_base;
        for (int i = 0; i < 64; i++) {
            MemoryInfo mi = {};
            u32 pi = 0;
            if (R_FAILED(svcQueryMemory(&mi, &pi, addr)) || !mi.size)
                break;
            if (mi.type == MemType_Unmapped)
                break;
            reserved_end = mi.addr + mi.size;
            addr = reserved_end;
        }
        g_libnx_heap_used = (reserved_end > heap_region_base)
                                ? ((reserved_end - heap_region_base + 0x1fffffull) & ~0x1fffffull)
                                : 0x10000000ull;
    }

    u64 aligned_req = (size + 0x1fffffull) & ~0x1fffffull;
    u64 want_game = g_compat_heap_reserved + g_vam_flat_used + aligned_req;
    if (want_game < g_game_heap_size) {
        nupLogf("hook SetMemoryHeapSize(req=0x%zx): keeping larger game=0x%llx\n",
                size, (unsigned long long)g_game_heap_size);
        return 0;
    }

    u64 total_mem = 0, used_mem = 0;
    svcGetInfo(&total_mem, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&used_mem, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    if (total_mem > used_mem + 0x1000000ull) {
        const u64 max_add = (total_mem - used_mem - 0x400000ull) & ~0x1fffffull;
        if (want_game > g_game_heap_size + max_add)
            want_game = g_game_heap_size + max_add;
    }

    void* out_heap = NULL;
    Result rc = svcSetHeapSize(&out_heap, (size_t)(g_libnx_heap_used + want_game));
    nupLogf("hook SetMemoryHeapSize(req=0x%zx): libnx=0x%llx game=0x%llx base=%p rc=0x%x\n",
            size, (unsigned long long)g_libnx_heap_used,
            (unsigned long long)want_game, out_heap, rc);
    if (R_SUCCEEDED(rc)) {
        if (!g_game_heap_base) {
            g_game_heap_base = (u64)(uintptr_t)out_heap + g_libnx_heap_used;
            g_game_heap_cursor = 0;
        }
        g_game_heap_size = want_game;
    }
    (void)real_SetMemoryHeapSize;
    return rc;
}

static uintptr_t hook_GetMemoryHeapAddress(void) {
    if (!g_game_heap_base)
        return 0;
    if (g_compat_heap_marked) {
        return (g_game_heap_size > g_compat_heap_reserved)
                   ? (uintptr_t)(g_game_heap_base + g_compat_heap_reserved)
                   : 0;
    }
    return (uintptr_t)g_game_heap_base;
}

static size_t hook_GetMemoryHeapSize(void) {
    if (g_compat_heap_marked) {
        return (g_game_heap_size > g_compat_heap_reserved)
                   ? (size_t)(g_game_heap_size - g_compat_heap_reserved)
                   : 0;
    }
    return (size_t)g_game_heap_size;
}

static u32 hook_AllocateMemoryBlock(uintptr_t* out_addr, size_t size) {
    const u64 aligned = (size + 0x1fffffull) & ~0x1fffffull;
    if (!g_game_heap_base || g_game_heap_cursor + aligned > g_game_heap_size) {
        nupLogf("hook AllocateMemoryBlock(0x%zx) FAILED (cur=0x%llx sz=0x%llx)\n",
                size, (unsigned long long)g_game_heap_cursor, (unsigned long long)g_game_heap_size);
        return MAKERESULT(3, 102);
    }
    const u64 res = g_game_heap_base + g_game_heap_cursor;
    g_game_heap_cursor += aligned;
    if (out_addr) *out_addr = (uintptr_t)res;
    nupLogf("hook AllocateMemoryBlock(0x%zx) -> 0x%llx\n", size, (unsigned long long)res);
    return 0;
}

static void hook_FreeMemoryBlock(uintptr_t addr, size_t size) { (void)addr; (void)size; }

static void log_std_alloc_init_diag(const char* tag, void* self, void* addr, size_t size, int is_cache) {
    if (g_std_alloc_init_logs >= 16)
        return;
    g_std_alloc_init_logs++;
    u64 sr_tot = 0, sr_used = 0, mem_tot = 0, mem_used = 0, ns_tot = 0, ns_used = 0;
    const Result rc_srt = svcGetInfo(&sr_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
    const Result rc_sru = svcGetInfo(&sr_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    const Result rc_mt  = svcGetInfo(&mem_tot, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
    const Result rc_mu  = svcGetInfo(&mem_used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    const Result rc_nst = svcGetInfo(&ns_tot, InfoType_TotalNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
    const Result rc_nsu = svcGetInfo(&ns_used, InfoType_UsedNonSystemMemorySize, CUR_PROCESS_HANDLE, 0);
    nupLogf("[alloc] %s(this=%p, addr=%p, size=0x%zx, cache=%d)\n",
            tag, self, addr, size, is_cache);
    nupLogf("  [sysres] tot=0x%llx(rc=0x%x) used=0x%llx(rc=0x%x) mem=0x%llx/0x%llx(rc=0x%x/0x%x) ns=0x%llx/0x%llx(rc=0x%x/0x%x)\n",
            (unsigned long long)sr_tot, rc_srt, (unsigned long long)sr_used, rc_sru,
            (unsigned long long)mem_used, (unsigned long long)mem_tot, rc_mu, rc_mt,
            (unsigned long long)ns_used, (unsigned long long)ns_tot, rc_nsu, rc_nst);
}

static void* try_alloc_vam_flat_fallback(size_t* io_size) {
    const u64 flat_sz = 0x98000000ULL; // 2.375 GiB flat arena (leaves >3.39 GiB for compat2 3 GiB GPU pool)
    const u64 prev_flat = g_vam_flat_used;
    if (R_FAILED(hook_SetMemoryHeapSize((size_t)flat_sz)))
        return NULL;
    uintptr_t block = 0;
    if (R_FAILED(hook_AllocateMemoryBlock(&block, (size_t)flat_sz)) || !block)
        return NULL;
    g_vam_flat_used = prev_flat + flat_sz;
    *io_size = (size_t)flat_sz;
    return (void*)block;
}

static bool needs_vam_flat_fallback(const void* addr, size_t size) {
    if (addr != NULL || size < 0x40000000ULL)
        return false;
    // Capability-driven: only substitute a flat heap arena when the donor lacks
    // SystemResourceSize (VAM disabled) and runtime SDK confirms VAM is disabled.
    if (g_caps.vam_capable)
        return false;
    return !(real_IsVamEnabled && real_IsVamEnabled());
}

static void hook_StdAllocInit2(void* self, void* addr, size_t size) {
    log_std_alloc_init_diag("StandardAllocator::Initialize(void*, size_t)", self, addr, size, -1);
    if (needs_vam_flat_fallback(addr, size)) {
        size_t flat_sz = size;
        void* flat_addr = try_alloc_vam_flat_fallback(&flat_sz);
        nupLogf("  -> [cap:vam=0 flat fallback] substituting addr=%p size=0x%zx\n", flat_addr, flat_sz);
        if (flat_addr) {
            addr = flat_addr;
            size = flat_sz;
        }
    }
    if (real_StdAllocInit2)
        real_StdAllocInit2(self, addr, size);
}

static void hook_StdAllocInit3(void* self, void* addr, size_t size, bool is_cache) {
    log_std_alloc_init_diag("StandardAllocator::Initialize(void*, size_t, bool)", self, addr, size, is_cache ? 1 : 0);
    if (needs_vam_flat_fallback(addr, size)) {
        size_t flat_sz = size;
        void* flat_addr = try_alloc_vam_flat_fallback(&flat_sz);
        nupLogf("  -> [cap:vam=0 flat fallback] substituting addr=%p size=0x%zx\n", flat_addr, flat_sz);
        if (flat_addr) {
            addr = flat_addr;
            size = flat_sz;
        }
    }
    if (real_StdAllocInit3)
        real_StdAllocInit3(self, addr, size, is_cache);
}

static void hook_StdAllocCtor2(void* self, void* addr, size_t size) {
    log_std_alloc_init_diag("StandardAllocator::StandardAllocator(void*, size_t)", self, addr, size, -1);
    if (needs_vam_flat_fallback(addr, size)) {
        size_t flat_sz = size;
        void* flat_addr = try_alloc_vam_flat_fallback(&flat_sz);
        nupLogf("  -> [cap:vam=0 flat fallback] substituting addr=%p size=0x%zx\n", flat_addr, flat_sz);
        if (flat_addr) {
            addr = flat_addr;
            size = flat_sz;
        }
    }
    if (real_StdAllocCtor2)
        real_StdAllocCtor2(self, addr, size);
}

static void hook_QueryMemoryInfo(void* out) {
    if (real_QueryMemoryInfo) real_QueryMemoryInfo(out);
    if (out) {
        u64* q = (u64*)out;
        const u64 orig_avail = q[0];
        const u64 orig_used = q[1];
        const u64 real_free = (orig_avail > orig_used) ? (orig_avail - orig_used) : 0;
        if (g_vam_flat_used > 0) {
            // Flat VAM fallback already committed 0x98000000 bytes in StandardAllocator;
            // report avail - used = 0x94000000 (2,368 MiB) so nninitStartup's Allocate(avail - used)
            // fits inside the flat StandardAllocator with 64 MiB metadata headroom.
            q[0] = 0xC0000000ULL;
            q[1] = 0x2C000000ULL;
        } else if (g_caps.target_is_switch1 && q[0] > 0xC0000000ULL) {
            // Switch 1 ABI expects <= 3 GiB available application RAM.
            // Exclude CompatibilityPack's hidden compat2 heap from totalUsedMemorySize so
            // (avail - used) cannot underflow when compat2 pre-allocates 3 GiB on Switch 2.
            if (g_compat_heap_reserved > 0 && q[1] >= g_compat_heap_reserved)
                q[1] -= g_compat_heap_reserved;
            q[0] = 0xC0000000ULL;
            // Guarantee reported free (q[0] - q[1]) never underflows and never exceeds
            // actual remaining physical RAM (leaving 64 MiB headroom for Horizon/NVN/threads).
            const u64 safe_free = (real_free > 0x4000000ULL)
                                      ? (real_free - 0x4000000ULL)
                                      : (real_free / 2ULL);
            if (q[1] >= q[0] || (q[0] - q[1]) > safe_free)
                q[1] = (q[0] > safe_free) ? (q[0] - safe_free) : 0;
        }
        // hook_SetMemoryHeapSize calls svcSetHeapSize directly, so sdk's cached heap size
        // (q[2]) stays 0 unless we synchronize it with the game's own tracked heap size
        // (excluding compat2's hidden heap).
        const u64 game_only_heap = (g_game_heap_size > g_compat_heap_reserved)
                                       ? (g_game_heap_size - g_compat_heap_reserved)
                                       : 0;
        if (game_only_heap > 0 && q[2] == 0)
            q[2] = game_only_heap;
        nupLogf("hook QueryMemoryInfo: avail=0x%llx (raw=0x%llx) used=0x%llx (raw=0x%llx compat=0x%llx) heap=0x%llx\n",
                (unsigned long long)q[0], (unsigned long long)orig_avail,
                (unsigned long long)q[1], (unsigned long long)orig_used,
                (unsigned long long)g_compat_heap_reserved,
                (unsigned long long)q[2]);
    }
}

static bool hook_GetAocListChangedEvent(void* out_sys_event) {
    // Capability-gated local event for SD-virtualized static DLC list:
    // initialize a real manual-clear local SystemEvent so Wait/Destroy semantics stay valid.
    if (out_sys_event) {
        typedef u32 (*CreateSysEvFn)(void*, int, bool);
        const u64 fn = elfFindSymbol(&g_mods, "_ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb");
        if (fn)
            ((CreateSysEvFn)(uintptr_t)fn)(out_sys_event, 0 /*ManualClear*/, false);
    }
    nupLogf("hook nn::aoc::GetAddOnContentListChangedEvent(%p) -> OK (dlcs=%d)\n",
            out_sys_event, g_dlc_count);
    return true;
}

static u32 hook_RoLookupSymbol(uintptr_t* out_addr, const char* sym_name) {
    if (!out_addr || !sym_name || !sym_name[0])
        return MAKERESULT(22, 5);
    // Two-step resolution: resolve original symbol first, then apply interposition registry.
    const u64 orig = elfFindSymbol(&g_mods, sym_name);
    const u64 interposed = hooksResolve(sym_name, orig);
    const u64 addr = interposed ? interposed : orig;
    if (addr) {
        if (nupTraceIsEnabled()) {
            nupLogBufferedf("[ro_lookup] '%s' -> 0x%llx%s\n", sym_name,
                            (unsigned long long)addr, interposed ? " [hooked]" : " [native]");
        }
        *out_addr = (uintptr_t)addr;
        return 0;
    }
    u32 rc = real_RoLookupSymbol ? real_RoLookupSymbol(out_addr, sym_name) : MAKERESULT(22, 5);
    if (nupTraceIsEnabled())
        nupLogBufferedf("[ro_lookup] '%s' -> real rc=0x%x addr=0x%llx\n",
                        sym_name, rc, (unsigned long long)(*out_addr));
    return rc;
}

static u32 hook_RoLookupModuleSymbol(uintptr_t* out_addr, const void* mod, const char* sym_name) {
    if (!out_addr || !sym_name || !sym_name[0])
        return MAKERESULT(22, 5);
    u32 rc = real_RoLookupModuleSymbol ? real_RoLookupModuleSymbol(out_addr, mod, sym_name) : MAKERESULT(22, 5);
    if (R_SUCCEEDED(rc) && *out_addr) {
        const u64 orig = (u64)(*out_addr);
        const u64 interposed = hooksResolve(sym_name, orig);
        if (interposed)
            *out_addr = (uintptr_t)interposed;
        if (nupTraceIsEnabled()) {
            nupLogBufferedf("[ro_mod_lookup] '%s' -> 0x%llx%s\n", sym_name,
                            (unsigned long long)(*out_addr), interposed ? " [hooked]" : " [native]");
        }
        return 0;
    }
    // Fallback to global auto-loaded module set if module-local lookup missed
    return hook_RoLookupSymbol(out_addr, sym_name);
}

static bool hook_IsVamEnabled(void) {
    const bool r = real_IsVamEnabled ? real_IsVamEnabled() : false;
    nupLogf("hook IsVirtualAddressMemoryEnabled() -> %d\n", r ? 1 : 0);
    return r;
}

static u32 g_alloc_pages_logs = 0;
static u32 g_alloc_pages_count = 0;
static u32 g_post_cap_logs = 0;
static u32 g_free_pages_logs = 0;
static bool g_in_nninit_startup = false;
static bool g_probe_capped = false;

static u32 hook_AllocAddrRegion(u64* out_addr, size_t size) {
    u64 s0 = 0, st = 0, s1 = 0;
    svcGetInfo(&st, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&s0, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    const u32 rc = real_AllocAddrRegion ? real_AllocAddrRegion(out_addr, size) : MAKERESULT(3, 102);
    svcGetInfo(&s1, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    nupLogf("hook AllocateAddressRegion(size=0x%zx) -> 0x%x addr=0x%llx (sysres: 0x%llx -> 0x%llx / 0x%llx)\n",
            size, rc, (unsigned long long)(out_addr ? *out_addr : 0),
            (unsigned long long)s0, (unsigned long long)s1, (unsigned long long)st);
    return rc;
}

static u32 hook_AllocMemPages(u64 addr, size_t size) {
    // During nninitStartup, Switch 1 titles that probe RAM in 1 MiB steps until 0x1203
    // can exhaust a 16 MiB SystemResource pool on 6.7 GiB Switch 2 hosts. Cap that probe
    // ONCE at 3 GiB (3072 x 1 MiB, matching Switch 1 RAM) based on Switch 1 ABI capability.
    if (g_caps.target_is_switch1 && g_in_nninit_startup && !g_probe_capped && size == 0x100000 && g_alloc_pages_count >= 3072) {
        g_probe_capped = true;
        u64 sys_tot = 0, sys_used = 0;
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        nupLogf("hook AllocateMemoryPages(addr=0x%llx, size=0x%zx) -> CAPPED ONCE 0x1203 (calls=%u sysres=0x%llx/0x%llx)\n",
                (unsigned long long)addr, size, g_alloc_pages_count,
                (unsigned long long)sys_used, (unsigned long long)sys_tot);
        return 0x1203;
    }

    const u32 rc = real_AllocMemPages ? real_AllocMemPages(addr, size) : MAKERESULT(3, 102);
    g_alloc_pages_count++;
    if (R_SUCCEEDED(rc))
        g_vam_backed_bytes += size;
    if (R_FAILED(rc)) {
        u64 sys_tot = 0, sys_used = 0, mem_tot = 0, mem_used = 0;
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&mem_tot, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&mem_used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
        const u64 phys_free = (mem_tot > mem_used) ? (mem_tot - mem_used) : 0;
        nupLogf("hook AllocateMemoryPages(addr=0x%llx, size=0x%zx) -> FAILED 0x%x (calls=%u backed=0x%llx phys_free=0x%llx sysres=0x%llx/0x%llx)\n",
                (unsigned long long)addr, size, rc, g_alloc_pages_count,
                (unsigned long long)g_vam_backed_bytes, (unsigned long long)phys_free,
                (unsigned long long)sys_used, (unsigned long long)sys_tot);
    } else if ((g_probe_capped && g_post_cap_logs < 16) ||
               size >= 0x1000000 || g_alloc_pages_logs < 6 || (g_alloc_pages_count % 512) == 0) {
        if (g_probe_capped) g_post_cap_logs++;
        else g_alloc_pages_logs++;
        u64 sys_tot = 0, sys_used = 0, mem_tot = 0, mem_used = 0;
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&mem_tot, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&mem_used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
        const u64 phys_free = (mem_tot > mem_used) ? (mem_tot - mem_used) : 0;
        nupLogf("hook AllocateMemoryPages #%u(addr=0x%llx, size=0x%zx) -> 0x%x (backed=0x%llx phys_free=0x%llx sysres=0x%llx/0x%llx)\n",
                g_alloc_pages_count, (unsigned long long)addr, size, rc,
                (unsigned long long)g_vam_backed_bytes, (unsigned long long)phys_free,
                (unsigned long long)sys_used, (unsigned long long)sys_tot);
    }
    return rc;
}

static u32 hook_FreeMemPages(u64 addr, size_t size) {
    const u32 rc = real_FreeMemPages ? real_FreeMemPages(addr, size) : MAKERESULT(3, 102);
    if (R_SUCCEEDED(rc)) {
        if (g_vam_backed_bytes >= size) g_vam_backed_bytes -= size;
        else g_vam_backed_bytes = 0;
    }
    if (R_FAILED(rc) || size >= 0x1000000 || g_free_pages_logs < 8) {
        g_free_pages_logs++;
        u64 sys_tot = 0, sys_used = 0;
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        nupLogf("hook FreeMemoryPages(addr=0x%llx, size=0x%zx) -> 0x%x (backed=0x%llx sysres=0x%llx/0x%llx)\n",
                (unsigned long long)addr, size, rc, (unsigned long long)g_vam_backed_bytes,
                (unsigned long long)sys_used, (unsigned long long)sys_tot);
    }
    return rc;
}

static void hook_ViInitialize(void) {
    nupLogf("hook nn::vi::Initialize()\n");
    if (real_ViInitialize) real_ViInitialize();
    nupLogf("hook nn::vi::Initialize() -> returned\n");
}

static u32 hook_ViOpenDefaultDisplay(void** out) {
    u32 rc = real_ViOpenDefaultDisplay ? real_ViOpenDefaultDisplay(out) : MAKERESULT(Module_Libnx, LibnxError_NotFound);
    nupLogf("hook nn::vi::OpenDefaultDisplay() -> 0x%x\n", rc);
    return rc;
}

static u32 hook_ViCreateLayer(void** out, void* disp) {
    u32 rc = real_ViCreateLayer ? real_ViCreateLayer(out, disp) : MAKERESULT(Module_Libnx, LibnxError_NotFound);
    nupLogf("hook nn::vi::CreateLayer() -> 0x%x\n", rc);
    return rc;
}

static void* (*real_NvnDeviceGetProcAddress)(void*, const char*) = NULL;
static u32 g_nvn_gpa_logs = 0;

static void* hook_NvnDeviceGetProcAddress(void* dev, const char* name) {
    void* fn = real_NvnDeviceGetProcAddress ? real_NvnDeviceGetProcAddress(dev, name) : NULL;
    if (nupTraceIsEnabled() && name && name[0]) {
        if (g_nvn_gpa_logs < 64) {
            g_nvn_gpa_logs++;
            nupLogBufferedf("  [nvn_gpa #%u] '%s' -> %p\n", g_nvn_gpa_logs, name, fn);
        }
        if (fn) {
            const u64 tramp = nupTraceWrapDynamicProc("nvn_gpa", name, (u64)(uintptr_t)fn);
            if (tramp)
                return (void*)(uintptr_t)tramp;
        }
    }
    return fn;
}

static void* hook_NvnBootstrapLoader(const char* name) {
    void* r = real_NvnBootstrapLoader ? real_NvnBootstrapLoader(name) : NULL;
    nupLogf("hook nvnBootstrapLoader('%s') -> %p\n", name ? name : "", r);
    if (nupTraceIsEnabled() && r && name && strcmp(name, "nvnDeviceGetProcAddress") == 0) {
        real_NvnDeviceGetProcAddress = (void* (*)(void*, const char*))r;
        g_nvn_gpa_logs = 0;
        nupLogf("  [trace] proxying nvnDeviceGetProcAddress for runtime NVN tracing\n");
        return (void*)hook_NvnDeviceGetProcAddress;
    }
    return r;
}

// --- Boot lifecycle trace hooks ---

static void log_used_mem(const char* tag) {
    u64 used = 0, sys_tot = 0, sys_used = 0;
    svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    nupLogf("[mem] %s: used=0x%llx sysres=0x%llx/0x%llx\n",
            tag, (unsigned long long)used,
            (unsigned long long)sys_used, (unsigned long long)sys_tot);
}

static void hook_init_libc1(void) {
    nupLogf("[6/6] entering _init_libc1 @ %p\n", (void*)real_init_libc1);
    if (real_init_libc1) real_init_libc1();
    nupLogf("[6/6] _init_libc1 returned\n");
    log_used_mem("after _init_libc1");
}

static volatile bool g_in_oe_init_applet = false;

static void hook_init_sdk_mod(void) {
    // Register exception handler + abort observers BEFORE compat2/SDK init so any
    // fault inside compat2 DT_INIT_ARRAY or nn::oe::InitializeApplet prints PC/LR/FAR!
    nupOnBeforeInitSdkModule();
    // Initialize CompatibilityParameter + SdkVersion + compat2/compat1 static constructors
    // BEFORE nninitInitializeSdkModule invokes compat2's nn::oe::InitializeApplet!
    elfInitSwitch1CompatParams(&g_mods);
    elfRunCompatInitArrays(&g_mods);
    hooksMarkCompatHeapEnd();
    nupLogf("[6/6] entering nninitInitializeSdkModule @ %p\n", (void*)real_init_sdk_mod);
    if (real_init_sdk_mod) real_init_sdk_mod();
    nupLogf("[6/6] nninitInitializeSdkModule returned\n");
    log_used_mem("after nninitInitializeSdkModule");
}

static void hook_OeInitApplet(void) {
    elfInitSwitch1CompatParams(&g_mods);
    elfRunCompatInitArrays(&g_mods);
    hooksMarkCompatHeapEnd();
    nupLogf("hook nn::oe::InitializeApplet() @ %p\n", (void*)real_OeInitApplet);
    g_in_oe_init_applet = true;
    if (real_OeInitApplet) real_OeInitApplet();
    g_in_oe_init_applet = false;
    nupLogf("hook nn::oe::InitializeApplet() -> returned\n");
}

static bool hook_AmInitAppInterfaces(void) {
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] -> nn::am::InitializeApplicationInterfaces()\n");
    bool r = real_AmInitAppInterfaces ? real_AmInitAppInterfaces() : false;
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] <- nn::am::InitializeApplicationInterfaces() -> %d\n", r ? 1 : 0);
    return r;
}

static u32 hook_SmFinalize(void) {
    u32 rc = real_SmFinalize ? real_SmFinalize() : 0;
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] nn::sm::Finalize() -> 0x%x\n", rc);
    return rc;
}

static void hook_AttachSysEvent(void* ev, u32 h, bool is_handle_managed, int clear_mode) {
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] AttachReadableHandleToSystemEvent(ev=%p, h=0x%x, managed=%d, clear=%d)\n",
                ev, h, is_handle_managed ? 1 : 0, clear_mode);
    if (real_AttachSysEvent)
        real_AttachSysEvent(ev, h, is_handle_managed, clear_mode);
}

static volatile u32 g_gpu_err_depth = 0;

static void hook_SetupGpuErrorHandler(void) {
    const u32 depth = __atomic_fetch_add(&g_gpu_err_depth, 1u, __ATOMIC_ACQ_REL) + 1u;
    if (g_in_oe_init_applet || depth > 1u) {
        nupLogf("  [oe_init] -> nn::oe::SetupGpuErrorHandler() (depth=%u, hook=%p, real=%p)\n",
                depth, (void*)hook_SetupGpuErrorHandler, (void*)real_SetupGpuErrorHandler);
    }
    if (depth > 2u) {
        nupLogf("  [oe_init] !!! RECURSION GUARD hit in hook_SetupGpuErrorHandler (depth=%u) — aborting recursion!\n", depth);
        __atomic_fetch_sub(&g_gpu_err_depth, 1u, __ATOMIC_ACQ_REL);
        return;
    }
    if (real_SetupGpuErrorHandler)
        real_SetupGpuErrorHandler();
    __atomic_fetch_sub(&g_gpu_err_depth, 1u, __ATOMIC_ACQ_REL);
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] <- nn::oe::SetupGpuErrorHandler() returned\n");
}

static void hook_WaitSystemEvent(void* ev) {
    if (g_in_oe_init_applet) {
        int focus = real_GetCurrentFocusState ? real_GetCurrentFocusState() : -1;
        nupLogf("  [oe_init] -> nn::os::WaitSystemEvent(ev=%p, focus=%d)\n", ev, focus);
    }
    if (real_WaitSystemEvent)
        real_WaitSystemEvent(ev);
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] <- nn::os::WaitSystemEvent(ev=%p)\n", ev);
}

static int hook_GetCurrentFocusState(void) {
    int st = real_GetCurrentFocusState ? real_GetCurrentFocusState() : 0;
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] nn::oe::GetCurrentFocusState() -> %d\n", st);
    return st;
}

static void hook_SetFocusHandlingMode(int mode) {
    if (g_in_oe_init_applet)
        nupLogf("  [oe_init] nn::oe::SetFocusHandlingMode(%d)\n", mode);
    if (real_SetFocusHandlingMode)
        real_SetFocusHandlingMode(mode);
}

static void hook_nninitStartup(void) {
    nupOnBeforeNninitStartup();
    nupLogf("[6/6] entering nninitStartup @ %p\n", (void*)real_nninitStartup);
    g_in_nninit_startup = true;
    g_probe_capped = false;
    g_alloc_pages_count = 0;
    g_post_cap_logs = 0;
    if (real_nninitStartup) real_nninitStartup();
    g_in_nninit_startup = false;
    nupLogf("[6/6] nninitStartup returned!\n");
    log_used_mem("after nninitStartup");
}

static void log_stack_mem(const void* stack, size_t stack_sz) {
    MemoryInfo mi = {};
    u32 pi = 0;
    Result qrc = svcQueryMemory(&mi, &pi, (u64)(uintptr_t)stack);
    nupLogf("  stack=%p sz=0x%zx mem(rc=0x%x base=0x%llx sz=0x%llx type=%u attr=0x%x perm=0x%x)\n",
            stack, stack_sz, qrc, (unsigned long long)mi.addr, (unsigned long long)mi.size,
            mi.type, mi.attr, mi.perm);
}

static u32 hook_CreateThread6(void* thread, void (*fn)(void*), void* arg, void* stack, size_t stack_sz, int prio) {
    if (g_create_thread_logs < 32) {
        g_create_thread_logs++;
        nupLogf("hook CreateThread6(t=%p fn=%p prio=%d stack=%p sz=0x%zx)\n",
                thread, (void*)fn, prio, stack, stack_sz);
        log_stack_mem(stack, stack_sz);
    }
    const u32 rc = real_CreateThread6 ? real_CreateThread6(thread, fn, arg, stack, stack_sz, prio) : MAKERESULT(3, 102);
    if (R_SUCCEEDED(rc))
        nupRecordWorkerThread(thread, (void*)fn);
    else
        nupLogf("hook CreateThread6(t=%p) -> FAILED 0x%x\n", thread, rc);
    return rc;
}

static u32 hook_CreateThread7(void* thread, void (*fn)(void*), void* arg, void* stack, size_t stack_sz, int prio, int core) {
    if (g_create_thread_logs < 32) {
        g_create_thread_logs++;
        u64 sys_tot = 0, sys_used = 0;
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        nupLogf("hook CreateThread7(t=%p fn=%p prio=%d core=%d stack=%p sz=0x%zx sysres=0x%llx/0x%llx)\n",
                thread, (void*)fn, prio, core, stack, stack_sz,
                (unsigned long long)sys_used, (unsigned long long)sys_tot);
        log_stack_mem(stack, stack_sz);
    }
    const u32 rc = real_CreateThread7 ? real_CreateThread7(thread, fn, arg, stack, stack_sz, prio, core) : MAKERESULT(3, 102);
    if (R_SUCCEEDED(rc))
        nupRecordWorkerThread(thread, (void*)fn);
    else
        nupLogf("hook CreateThread7(t=%p) -> FAILED 0x%x\n", thread, rc);
    return rc;
}

static bool hook_MapAliasStack(const void* self, void** out_stack, const void* stack, size_t stack_sz) {
    const bool ok = real_MapAliasStack ? real_MapAliasStack(self, out_stack, stack, stack_sz) : false;
    if (!ok) {
        u64 sr_addr = 0, sr_sz = 0, used = 0, tot = 0, sys_tot = 0, sys_used = 0;
        svcGetInfo(&sr_addr, InfoType_StackRegionAddress, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sr_sz, InfoType_StackRegionSize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&tot, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
        nupLogf("hook MapAliasStack(stack=%p sz=0x%zx) -> FAILED! sr=[0x%llx+0x%llx] used=0x%llx/0x%llx sysres=0x%llx/0x%llx\n",
                stack, stack_sz, (unsigned long long)sr_addr, (unsigned long long)sr_sz,
                (unsigned long long)used, (unsigned long long)tot,
                (unsigned long long)sys_used, (unsigned long long)sys_tot);
        log_stack_mem(stack, stack_sz);

        // Probe svcMapMemory strictly inside [sr_addr, sr_addr + sr_sz)
        u64 cur = sr_addr;
        const u64 end = sr_addr + sr_sz;
        for (int i = 0; i < 64 && cur < end; i++) {
            MemoryInfo mi = {};
            u32 pi = 0;
            if (R_FAILED(svcQueryMemory(&mi, &pi, cur)) || !mi.size)
                break;
            u64 lo = mi.addr < sr_addr ? sr_addr : mi.addr;
            u64 hi = (mi.addr + mi.size) > end ? end : (mi.addr + mi.size);
            if (mi.type == MemType_Unmapped && hi > lo && (hi - lo) >= stack_sz + 0x20000) {
                const u64 probe_dst = (lo + 0x10000ULL + 0xffffULL) & ~0xffffULL;
                if (probe_dst >= sr_addr && probe_dst + stack_sz <= end) {
                    const Result mrc = svcMapMemory((void*)(uintptr_t)probe_dst, (void*)(uintptr_t)stack, stack_sz);
                    nupLogf("  probe svcMapMemory(dst=0x%llx, src=%p, sz=0x%zx) -> rc=0x%x\n",
                            (unsigned long long)probe_dst, stack, stack_sz, mrc);
                    if (R_SUCCEEDED(mrc)) {
                        if (out_stack) *out_stack = (void*)(uintptr_t)probe_dst;
                        nupLogf("  -> recovered MapAliasStack with dst=0x%llx!\n", (unsigned long long)probe_dst);
                        return true;
                    }
                    break;
                }
            }
            cur = mi.addr + mi.size;
        }
    }
    return ok;
}

static u32 g_set_thread_name_logs = 0;

static void hook_SetThreadName(void* thread, const char* name) {
    nupRecordWorkerThreadName(thread, name);
    if (g_set_thread_name_logs < 48) {
        g_set_thread_name_logs++;
        nupLogf("hook SetThreadName(t=%p, '%s')\n", thread, name ? name : "(null)");
    }
    if (real_SetThreadName) real_SetThreadName(thread, name);
}

static void hook_SetThreadNamePtr(void* thread, const char* name) {
    nupRecordWorkerThreadName(thread, name);
    if (g_set_thread_name_logs < 48) {
        g_set_thread_name_logs++;
        nupLogf("hook SetThreadNamePointer(t=%p, '%s')\n", thread, name ? name : "(null)");
    }
    if (real_SetThreadNamePtr) real_SetThreadNamePtr(thread, name);
}

static int hook_GetHostArgc(void) {
    const int argc = real_GetHostArgc ? real_GetHostArgc() : 0;
    nupLogf("hook nn::os::GetHostArgc() -> %d\n", argc);
    return argc;
}

static char g_safe_argv0[] = "";
static char* g_safe_argv[] = { g_safe_argv0, NULL };

static char** hook_GetHostArgv(void) {
    char** argv = real_GetHostArgv ? real_GetHostArgv() : NULL;
    char* p0 = NULL;
    const char* a0 = NULL;
    if (argv) {
        MemoryInfo mi = {};
        u32 pi = 0;
        if (R_SUCCEEDED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)argv)) && (mi.perm & Perm_R)) {
            p0 = argv[0];
            if (p0 && R_SUCCEEDED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)p0)) && (mi.perm & Perm_R))
                a0 = p0;
        }
    }
    nupLogf("hook nn::os::GetHostArgv() -> %p (argv[0]=%p '%s')\n",
            (void*)argv, (void*)p0, a0 ? a0 : "<null/unreadable>");
    if (!argv || !a0) {
        nupLogf("  -> substituting safe empty host argv={\"\", NULL}\n");
        return g_safe_argv;
    }
    return argv;
}

static void hook_GetProcessNamePointer(const char** out_name, u64* out_len) {
    static const char fallback[] = "Application";
    const char* name = (g_caps.target_npdm_valid && g_caps.target_proc_name[0])
                           ? g_caps.target_proc_name : fallback;
    if (out_name) *out_name = name;
    if (out_len) *out_len = strlen(name);
}

static void hook_nnMain(void) {
    log_used_mem("before nnMain");
    nupOnBeforeNnMain();
    nupLogf("[6/6] entering nnMain @ %p\n", (void*)real_nnMain);
    if (real_nnMain) real_nnMain();
    nupLogf("[6/6] nnMain returned!\n");
}

static void hook_AbortImpl0(void) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogBacktrace("nn::diag::detail::AbortImpl()", caller, 0, 0);
    if (real_AbortImpl0) real_AbortImpl0();
}

static void hook_AbortImplRes(const u32* res) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    const u32 val = res ? *res : 0;
    nupLogBacktrace("nn::diag::detail::AbortImpl(Result)", caller, val, (u64)(uintptr_t)res);
    if (real_AbortImplRes) real_AbortImplRes(res);
}

static void hook_StdTerminate(void) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogBacktrace("std::terminate()", caller, 0, 0);
    if (real_StdTerminate) real_StdTerminate();
}

static void hook_AssertFail(const char* expr, const char* file, int line, const char* func) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogf("!!! __assert_fail: expr='%s' file='%s':%d func='%s'\n",
            expr ? expr : "?", file ? file : "?", line, func ? func : "?");
    nupLogBacktrace("__assert_fail", caller, (u64)line, 0);
    if (real_AssertFail) real_AssertFail(expr, file, line, func);
}

static void hook_LibcppVerboseAbort(const char* fmt, ...) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogf("!!! __libcpp_verbose_abort: fmt='%s'\n", fmt ? fmt : "?");
    nupLogBacktrace("__libcpp_verbose_abort", caller, 0, 0);
    if (real_LibcppVerboseAbort) real_LibcppVerboseAbort(fmt);
}

static void hook_ThrowSystemError(int ev, const char* what) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogf("!!! __throw_system_error: ev=%d what='%s'\n", ev, what ? what : "?");
    nupLogBacktrace("__throw_system_error", caller, (u64)ev, 0);
    if (real_ThrowSystemError) real_ThrowSystemError(ev, what);
}

// --- Unified Compatibility Provider Registry ---

typedef struct {
    const char* sym_name;
    void* hook_fn;
    void** real_slot;
    HookProviderKind provider;
    bool terminal_for_compat; // Safe to return from LookupNextSymbolForCompat (never recurses into compat)
} HookProviderEntry;

#define PROV_ONLY(sym, fn, prov, term)   { (sym), (void*)(fn), NULL, (prov), (term) }
#define PROV_WRAP(sym, fn, real, prov, term) { (sym), (void*)(fn), (void**)&(real), (prov), (term) }

static const HookProviderEntry g_hook_registry[] = {
    // 1. FS VFS Provider (RomFS, Saves, DeviceSave, Cache, Temp, BCAT, File & Dir I/O -> SD)
    PROV_ONLY("_ZN2nn2fs22QueryMountRomCacheSizeEPm", hook_QueryMountRomCacheSize1, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs22QueryMountRomCacheSizeEPmNS_13ApplicationIdE", hook_QueryMountRomCacheSizeAppId, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs22QueryMountRomCacheSizeEPmi", hook_QueryMountRomCacheSizeIdx, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs8MountRomEPKc", hook_MountRom1, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs8MountRomEPKcPvm", hook_MountRom3, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs8MountRomEPKcNS_13ApplicationIdEPvm", hook_MountRomAppId, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs8MountRomEPKciPvm", hook_MountRomIdx, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs11CanMountRomENS_13ApplicationIdE", hook_CanMountRom, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs7UnmountEPKc", hook_Unmount, real_Unmount, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs9IsMountedEPKc", hook_IsMounted, real_IsMounted, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs13IsPathMountedEPKc", hook_IsPathMounted, real_IsPathMounted, HOOK_PROV_FS, true),

    PROV_ONLY("_ZN2nn2fs13MountSaveDataEPKcRKNS_7account3UidE", hook_MountSaveDataUid, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs13MountSaveDataEPKcNS0_6UserIdE", hook_MountSaveDataUserId, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs13MountSaveDataEPKcNS_13ApplicationIdERKNS_7account3UidE", hook_MountSaveDataAppUid, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs13MountSaveDataEPKcNS_3ncm13ApplicationIdENS0_6UserIdE", hook_MountSaveDataAppUserId, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs21MountSaveDataReadOnlyEPKcNS_13ApplicationIdERKNS_7account3UidE", hook_MountSaveDataReadOnlyUid, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs21MountSaveDataReadOnlyEPKcNS_3ncm13ApplicationIdENS0_6UserIdE", hook_MountSaveDataReadOnlyUserId, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs21MountSaveDataForDebugEPKc", hook_MountSaveDataForDebug, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs14EnsureSaveDataERKNS_7account3UidE", hook_EnsureSaveData, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18IsSaveDataExistingERKNS_7account3UidE", hook_IsSaveDataExistingUid, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18IsSaveDataExistingENS_13ApplicationIdERKNS_7account3UidE", hook_IsSaveDataExistingAppUid, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18IsSaveDataExistingEPbRKNS_7account3UidE", hook_IsSaveDataExistingOutUid, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18IsSaveDataExistingEPbNS_13ApplicationIdERKNS_7account3UidE", hook_IsSaveDataExistingOutAppUid, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs19MountDeviceSaveDataEPKc", hook_MountDeviceSaveData1, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs19MountDeviceSaveDataEPKcNS_13ApplicationIdE", hook_MountDeviceSaveDataApp, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs19MountDeviceSaveDataEPKcNS_3ncm13ApplicationIdE", hook_MountDeviceSaveDataApp, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs24IsDeviceSaveDataExistingENS_13ApplicationIdE", hook_IsDeviceSaveDataExisting, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs17MountCacheStorageEPKc", hook_MountCacheStorage1, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs17MountCacheStorageEPKci", hook_MountCacheStorageIdx, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs17MountCacheStorageEPKcNS_3ncm13ApplicationIdE", hook_MountCacheStorageApp, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs17MountCacheStorageEPKcNS_3ncm13ApplicationIdEi", hook_MountCacheStorageAppIdx, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18CreateCacheStorageEill", hook_CreateCacheStorageIdx, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18DeleteCacheStorageEi", hook_DeleteCacheStorageIdx, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs21MountTemporaryStorageEPKc", hook_MountTemporaryStorage, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs17MountBcatSaveDataEPKcNS_3ncm13ApplicationIdE", hook_MountBcatSaveData, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs14ExtendSaveDataERKNS_7account3UidEll", hook_ExtendSaveData, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs20ExtendDeviceSaveDataEll", hook_ExtendDeviceSaveData, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs15GetSaveDataSizeEPlS1_RKNS_7account3UidE", hook_GetSaveDataSize, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18GetSaveDataSizeMaxEPlS1_", hook_GetSaveDataSizeMax, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs21GetDeviceSaveDataSizeEPlS1_", hook_GetDeviceSaveDataSize1, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs21GetDeviceSaveDataSizeEPlS1_NS_13ApplicationIdE", hook_GetDeviceSaveDataSizeApp, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs24GetDeviceSaveDataSizeMaxEPlS1_", hook_GetSaveDataSizeMax, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs19GetCacheStorageSizeEPlS1_i", hook_GetCacheStorageSize, HOOK_PROV_FS, true),
    PROV_ONLY("_ZN2nn2fs18GetCacheStorageMaxEPiPl", hook_GetCacheStorageMax, HOOK_PROV_FS, true),

    PROV_WRAP("_ZN2nn2fs12GetEntryTypeEPNS0_18DirectoryEntryTypeEPKc", hook_GetEntryType, real_GetEntryType, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs8OpenFileEPNS0_10FileHandleEPKci", hook_OpenFile, real_OpenFile, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs8ReadFileENS0_10FileHandleElPvm", hook_ReadFile4, real_ReadFile4, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs8ReadFileENS0_10FileHandleElPvmRKNS0_10ReadOptionE", hook_ReadFile5Opt, real_ReadFile5Opt, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvm", hook_ReadFile5Out, real_ReadFile5Out, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvmRKNS0_10ReadOptionE", hook_ReadFile6, real_ReadFile6, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs14ReadFileAtOnceEPKcPvm", hook_ReadFileAtOnce, real_ReadFileAtOnce, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs9WriteFileENS0_10FileHandleElPKvmRKNS0_11WriteOptionE", hook_WriteFile, real_WriteFile, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs9FlushFileENS0_10FileHandleE", hook_FlushFile, real_FlushFile, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs11SetFileSizeENS0_10FileHandleEl", hook_SetFileSize, real_SetFileSize, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs11GetFileSizeEPlNS0_10FileHandleE", hook_GetFileSize, real_GetFileSize, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs15GetFileOpenModeENS0_10FileHandleE", hook_GetFileOpenMode, real_GetFileOpenMode, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs9CloseFileENS0_10FileHandleE", hook_CloseFile, real_CloseFile, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs10CreateFileEPKcl", hook_CreateFile2, real_CreateFile2, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs10CreateFileEPKcli", hook_CreateFile3, real_CreateFile3, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs24CreateAndWriteFileAtOnceEPKcPKvm", hook_CreateAndWriteFileAtOnce, real_CreateAndWriteFileAtOnce, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs10DeleteFileEPKc", hook_DeleteFile, real_DeleteFile, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs10RenameFileEPKcS2_", hook_RenameFile, real_RenameFile, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs15CreateDirectoryEPKc", hook_CreateDirectory, real_CreateDirectory, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs15DeleteDirectoryEPKc", hook_DeleteDirectory, real_DeleteDirectory, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs26DeleteDirectoryRecursivelyEPKc", hook_DeleteDirectoryRec, real_DeleteDirectoryRec, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs25CleanDirectoryRecursivelyEPKc", hook_CleanDirectoryRec, real_CleanDirectoryRec, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs15RenameDirectoryEPKcS2_", hook_RenameDirectory, real_RenameDirectory, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs16GetFreeSpaceSizeEPlPKc", hook_GetFreeSpaceSize, real_GetFreeSpaceSize, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs17GetTotalSpaceSizeEPlPKc", hook_GetTotalSpaceSize, real_GetTotalSpaceSize, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs6CommitEPKc", hook_Commit1, real_Commit1, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs6CommitEPKcRKNS0_12CommitOptionE", hook_Commit2, real_Commit2, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs6CommitEPKPKci", hook_CommitMulti, real_CommitMulti, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs14CommitSaveDataEPKc", hook_CommitSaveData, real_CommitSaveData, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs13OpenDirectoryEPNS0_15DirectoryHandleEPKci", hook_OpenDirectory, real_OpenDirectory, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs13ReadDirectoryEPlPNS0_14DirectoryEntryENS0_15DirectoryHandleEl", hook_ReadDirectory, real_ReadDirectory, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs22GetDirectoryEntryCountEPlNS0_15DirectoryHandleE", hook_GetDirEntryCount, real_GetDirEntryCount, HOOK_PROV_FS, true),
    PROV_WRAP("_ZN2nn2fs14CloseDirectoryENS0_15DirectoryHandleE", hook_CloseDirectory, real_CloseDirectory, HOOK_PROV_FS, true),

    // 2. AOC / DLC Provider -> SD card
    PROV_ONLY("_ZN2nn3aoc17CountAddOnContentEv", hook_CountAddOnContent, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc16ListAddOnContentEPiii", hook_ListAddOnContent, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc21GetAddOnContentBaseIdEv", hook_GetAddOnContentBaseId, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc19PrepareAddOnContentEi", hook_PrepareAddOnContent, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc16UpdateCachedListEv", hook_AocNoopVoid, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc28CheckAddOnContentMountStatusEv", hook_AocOkU32, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc23NotifyMountAddOnContentENS_3ncm6DataIdE", hook_NotifyAocDataId, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc25NotifyUnmountAddOnContentENS_3ncm6DataIdE", hook_NotifyAocDataId, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn3aoc31GetAddOnContentListChangedEventEPNS_2os11SystemEventE", hook_GetAocListChangedEvent, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn2fs31QueryMountAddOnContentCacheSizeEPmi", hook_QueryMountAddOnContentCacheSize, HOOK_PROV_AOC, true),
    PROV_ONLY("_ZN2nn2fs17MountAddOnContentEPKciPvm", hook_MountAddOnContent, HOOK_PROV_AOC, true),

    // 3. Memory Provider (synchronized heap size/address, QueryMemoryInfo, VAM)
    PROV_WRAP("_ZN2nn2os17SetMemoryHeapSizeEm", hook_SetMemoryHeapSize, real_SetMemoryHeapSize, HOOK_PROV_MEM, true),
    PROV_ONLY("_ZN2nn2os20GetMemoryHeapAddressEv", hook_GetMemoryHeapAddress, HOOK_PROV_MEM, true),
    PROV_ONLY("_ZN2nn2os17GetMemoryHeapSizeEv", hook_GetMemoryHeapSize, HOOK_PROV_MEM, true),
    PROV_ONLY("_ZN2nn2os19AllocateMemoryBlockEPmm", hook_AllocateMemoryBlock, HOOK_PROV_MEM, true),
    PROV_ONLY("_ZN2nn2os15FreeMemoryBlockEmm", hook_FreeMemoryBlock, HOOK_PROV_MEM, true),
    PROV_WRAP("_ZN2nn2os15QueryMemoryInfoEPNS0_10MemoryInfoE", hook_QueryMemoryInfo, real_QueryMemoryInfo, HOOK_PROV_MEM, true),
    PROV_WRAP("_ZN2nn2os29IsVirtualAddressMemoryEnabledEv", hook_IsVamEnabled, real_IsVamEnabled, HOOK_PROV_MEM, false),
    PROV_WRAP("_ZN2nn2os21AllocateAddressRegionEPmm", hook_AllocAddrRegion, real_AllocAddrRegion, HOOK_PROV_MEM, false),
    PROV_WRAP("_ZN2nn2os19AllocateMemoryPagesEmm", hook_AllocMemPages, real_AllocMemPages, HOOK_PROV_MEM, false),
    PROV_WRAP("_ZN2nn2os15FreeMemoryPagesEmm", hook_FreeMemPages, real_FreeMemPages, HOOK_PROV_MEM, false),

    // 4. Allocator Provider (StandardAllocator Initialize overloads + 2-arg ctor)
    PROV_WRAP("_ZN2nn3mem17StandardAllocator10InitializeEPvm", hook_StdAllocInit2, real_StdAllocInit2, HOOK_PROV_ALLOC, false),
    PROV_WRAP("_ZN2nn3mem17StandardAllocator10InitializeEPvmb", hook_StdAllocInit3, real_StdAllocInit3, HOOK_PROV_ALLOC, false),
    PROV_WRAP("_ZN2nn3mem17StandardAllocatorC1EPvm", hook_StdAllocCtor2, real_StdAllocCtor2, HOOK_PROV_ALLOC, false),

    // 5. RTLD / Dynamic Symbol Resolution Provider
    PROV_WRAP("_ZN2nn2ro12LookupSymbolEPmPKc", hook_RoLookupSymbol, real_RoLookupSymbol, HOOK_PROV_RTLD, false),
    PROV_WRAP("_ZN2nn2ro18LookupModuleSymbolEPmPKNS0_6ModuleEPKc", hook_RoLookupModuleSymbol, real_RoLookupModuleSymbol, HOOK_PROV_RTLD, false),

    // 6. Service Proxy, Graphics, Threading & Boot/Abort Diagnostics Provider
    PROV_WRAP("_ZN2nn2sm16GetServiceHandleEPNS_3svc6HandleEPKcm", hook_GetServiceHandle, real_GetServiceHandle, HOOK_PROV_SVC, true),
    PROV_WRAP("_ZN2nn2vi10InitializeEv", hook_ViInitialize, real_ViInitialize, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE", hook_ViOpenDefaultDisplay, real_ViOpenDefaultDisplay, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE", hook_ViCreateLayer, real_ViCreateLayer, HOOK_PROV_SVC, false),
    PROV_WRAP("nvnBootstrapLoader", hook_NvnBootstrapLoader, real_NvnBootstrapLoader, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os12CreateThreadEPNS0_10ThreadTypeEPFvPvES3_S3_mi", hook_CreateThread6, real_CreateThread6, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os12CreateThreadEPNS0_10ThreadTypeEPFvPvES3_S3_mii", hook_CreateThread7, real_CreateThread7, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZNK2nn2os6detail26ThreadManagerImplByHorizon13MapAliasStackEPPvPKvm", hook_MapAliasStack, real_MapAliasStack, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os13SetThreadNameEPNS0_10ThreadTypeEPKc", hook_SetThreadName, real_SetThreadName, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os20SetThreadNamePointerEPNS0_10ThreadTypeEPKc", hook_SetThreadNamePtr, real_SetThreadNamePtr, HOOK_PROV_SVC, false),

    PROV_WRAP("_init_libc1", hook_init_libc1, real_init_libc1, HOOK_PROV_SVC, false),
    PROV_WRAP("nninitInitializeSdkModule", hook_init_sdk_mod, real_init_sdk_mod, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2oe16InitializeAppletEv", hook_OeInitApplet, real_OeInitApplet, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2am31InitializeApplicationInterfacesEv", hook_AmInitAppInterfaces, real_AmInitAppInterfaces, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2sm8FinalizeEv", hook_SmFinalize, real_SmFinalize, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os33AttachReadableHandleToSystemEventEPNS0_15SystemEventTypeEjbNS0_14EventClearModeE", hook_AttachSysEvent, real_AttachSysEvent, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2oe20SetupGpuErrorHandlerEv", hook_SetupGpuErrorHandler, real_SetupGpuErrorHandler, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os15WaitSystemEventEPNS0_15SystemEventTypeE", hook_WaitSystemEvent, real_WaitSystemEvent, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2oe20GetCurrentFocusStateEv", hook_GetCurrentFocusState, real_GetCurrentFocusState, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2oe20SetFocusHandlingModeENS0_17FocusHandlingModeE", hook_SetFocusHandlingMode, real_SetFocusHandlingMode, HOOK_PROV_SVC, false),
    PROV_WRAP("nninitStartup", hook_nninitStartup, real_nninitStartup, HOOK_PROV_SVC, false),
    PROV_WRAP("nnMain", hook_nnMain, real_nnMain, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os11GetHostArgcEv", hook_GetHostArgc, real_GetHostArgc, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os11GetHostArgvEv", hook_GetHostArgv, real_GetHostArgv, HOOK_PROV_SVC, false),
    PROV_ONLY("_ZN2nn4diag6detail21GetProcessNamePointerEPPKcPm", hook_GetProcessNamePointer, HOOK_PROV_SVC, true),
    PROV_WRAP("_ZN2nn4diag6detail9AbortImplEv", hook_AbortImpl0, real_AbortImpl0, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn4diag6detail9AbortImplEPKNS_6ResultE", hook_AbortImplRes, real_AbortImplRes, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZSt9terminatev", hook_StdTerminate, real_StdTerminate, HOOK_PROV_SVC, false),
    PROV_WRAP("__assert_fail", hook_AssertFail, real_AssertFail, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZNSt3__122__libcpp_verbose_abortEPKcz", hook_LibcppVerboseAbort, real_LibcppVerboseAbort, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZNSt3__120__throw_system_errorEiPKc", hook_ThrowSystemError, real_ThrowSystemError, HOOK_PROV_SVC, false),
};

static const HookProviderEntry* find_registry_entry(const char* sym_name) {
    if (!sym_name || !sym_name[0])
        return NULL;
    const size_t n = sizeof(g_hook_registry) / sizeof(g_hook_registry[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(sym_name, g_hook_registry[i].sym_name) == 0)
            return &g_hook_registry[i];
    }
    return NULL;
}

const char* hooksProviderName(HookProviderKind kind) {
    switch (kind) {
    case HOOK_PROV_FS:    return "FS";
    case HOOK_PROV_AOC:   return "AOC";
    case HOOK_PROV_MEM:   return "MEM";
    case HOOK_PROV_ALLOC: return "ALLOC";
    case HOOK_PROV_RTLD:  return "RTLD";
    case HOOK_PROV_SVC:   return "SVC";
    default:              return "NONE";
    }
}

HookProviderKind hooksQueryProvider(const char* sym_name, bool* out_terminal_for_compat) {
    const HookProviderEntry* e = find_registry_entry(sym_name);
    if (!e) {
        if (out_terminal_for_compat) *out_terminal_for_compat = false;
        return HOOK_PROV_NONE;
    }
    if (out_terminal_for_compat) *out_terminal_for_compat = e->terminal_for_compat;
    return e->provider;
}

u64 hooksResolve(const char* sym_name, u64 real_addr) {
    const HookProviderEntry* e = find_registry_entry(sym_name);
    if (!e)
        return 0;
    if (real_addr && e->real_slot)
        *e->real_slot = (void*)(uintptr_t)real_addr;
    return (u64)(uintptr_t)e->hook_fn;
}

u32 hooksLookupNextForCompat(uintptr_t* out_addr, const char* sym_name) {
    if (!out_addr || !sym_name || !sym_name[0])
        return MAKERESULT(22, 5); // 0xa16 (nn::ro SymbolNotFound)

    // 1. Pure original-symbol lookup strictly AFTER the calling module
    //    (compat1 -> compat2/sdk, compat2 -> sdk). Never returns caller or passthrough hooks.
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    const char* caller_mod = "?";
    const char* found_mod = "?";
    u64 orig_addr = elfFindSymbolAfterAddr(&g_mods, caller, sym_name, &caller_mod, &found_mod);

    // 2. Apply unified provider registry ONLY for entries marked terminal_for_compat.
    bool is_terminal = false;
    const HookProviderKind prov = hooksQueryProvider(sym_name, &is_terminal);
    u64 addr = orig_addr;
    bool used_hook = false;
    if (prov != HOOK_PROV_NONE && is_terminal) {
        const u64 hooked = hooksResolve(sym_name, orig_addr);
        if (hooked) {
            addr = hooked;
            used_hook = true;
        }
    }
    if (!addr) {
        nupLogf("[compat] LookupNextSymbolForCompat('%s' from %s) -> NOT FOUND\n", sym_name, caller_mod);
        *out_addr = 0;
        return MAKERESULT(22, 5); // 0xa16
    }
    if (nupTraceIsEnabled()) {
        nupLogBufferedf("[compat_next] '%s' (%s -> %s) -> 0x%llx%s\n",
                        sym_name, caller_mod, found_mod,
                        (unsigned long long)addr, used_hook ? " [terminal-hook]" : "");
        if (!used_hook) {
            const u64 tramp = nupTraceWrapPlt("compat_next", sym_name, addr);
            if (tramp)
                addr = tramp;
        }
    }
    *out_addr = (uintptr_t)addr;
    return 0;
}
