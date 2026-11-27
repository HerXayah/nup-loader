// SPDX-License-Identifier: MIT
#include "svc_hipc.h"
#include "elf_loader.h"
#include "log.h"
#include "nupvfs_proto.h"
#include "trace.h"
#include "vfs_romfs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Virtual kernel handle & domain object ID ranges (never collide with real kernel/FS IDs)
#define VHANDLE_BASE    0x5E000000u
#define VHANDLE_MASK    0xFF000000u
#define VHANDLE_MAX     512

#define VOBJ_BASE       0x4E500000u
#define VOBJ_MASK       0xFFF00000u
#define VOBJ_MAX        1024

#define MAX_SESSIONS    1024
#define MAX_DLC_SLOTS   64
#define MAX_PROG_ROMS   8

#define FS_RC_PATH_NOT_FOUND        MAKERESULT(2, 1)
#define FS_RC_TARGET_NOT_FOUND      MAKERESULT(2, 1002) // 0x7D402
#define FS_RC_UNSUPPORTED           MAKERESULT(2, 6300) // 0x313802
#define FS_RC_PERMISSION_DENIED     MAKERESULT(2, 6400)
#define FS_RC_INVALID_ARG           MAKERESULT(2, 6002)
#define FS_RC_NAND_BLOCKED          0x2EE202u

typedef enum {
    SESS_NONE = 0,
    SESS_SM,
    SESS_FSP_SRV,
    SESS_LDR_RO,
    SESS_AOC,
    SESS_BCAT,
} TrackedSessionKind;

typedef struct {
    Handle handle;
    TrackedSessionKind kind;
    bool is_domain;
} TrackedSession;

typedef enum {
    VOBJ_NONE = 0,
    VOBJ_STORAGE,
    VOBJ_FS,
    VOBJ_FILE,
    VOBJ_DIR,
    VOBJ_EVENT,
    VOBJ_SAVE_READER,
    VOBJ_STANDIN,
} VObjKind;

typedef struct {
    VObjKind kind;
    bool read_only;
    bool is_domain;         // For VOBJ_STANDIN
    u32 reader_pos;         // For VOBJ_SAVE_READER
    char standin_name[12];  // For VOBJ_STANDIN
    VfsRomfs* romfs;        // For VOBJ_STORAGE (non-owning pointer)
    char sd_root[0x300];    // For VOBJ_FS
    FsFile file;            // For VOBJ_FILE
    FsDir dir;              // For VOBJ_DIR
    s64 cached_size;        // For VOBJ_FILE
} VirtualObj;

typedef struct {
    int index;
    char sd_root[0x300];
    VfsRomfs romfs;
    bool romfs_built;
} DlcSlot;

static NupArchive* g_nup = NULL;
static FsFileSystem* g_sd = NULL;
static NupRuntimeCapabilities g_caps = {};
static u64 g_title_id = 0;
static Handle g_hen_sm = INVALID_HANDLE;
static Handle g_preopened_nv = INVALID_HANDLE;
static Service g_vfs_plugin = {};
static bool g_vfs_plugin_ok = false;
static u32 g_vfs_flags = NUPVFS_FLAG_MODS | NUPVFS_FLAG_CACHE;
static NupSpinLock g_vfs_ipc_lock;

static u64 g_host_heap_base = 0;
static u64 g_host_heap_keep = 0;
static u64 g_game_heap_size = 0;
static u64 g_compat_heap_reserved = 0;
static bool g_compat_heap_marked = false;
static volatile int g_in_startup = 0;
static volatile u32 g_vam_1m_calls = 0;
static volatile int g_vam_probe_capped = 0;
static volatile u32 g_ro_loaded_cnt = 0;

static NupSpinLock g_svc_lock;
static TrackedSession g_sessions[MAX_SESSIONS] = {};
static VirtualObj g_vobjs[VOBJ_MAX] = {};
static VirtualObj g_vhandles[VHANDLE_MAX] = {};

static bool g_has_rom_overlay = false;
static char g_rom_overlay_root[0x300] = {};

static VfsRomfs g_active_romfs = {};
static bool g_active_romfs_built = false;
static VfsRomfs g_prog_romfs[MAX_PROG_ROMS] = {};
static bool g_prog_romfs_built[MAX_PROG_ROMS] = {};

static DlcSlot g_dlcs[MAX_DLC_SLOTS] = {};
static int g_dlc_count = 0;

// --- Little-endian & string helpers ---

static inline u32 rd32(const u8* p) { u32 v; memcpy(&v, p, 4); return v; }
static inline u64 rd64(const u8* p) { u64 v; memcpy(&v, p, 8); return v; }
static inline void wr32(u8* p, u32 v) { memcpy(p, &v, 4); }
static inline void wr64(u8* p, u64 v) { memcpy(p, &v, 8); }

static bool is_vhandle(Handle h) {
    return (h & VHANDLE_MASK) == VHANDLE_BASE && (h - VHANDLE_BASE) < VHANDLE_MAX;
}

static bool is_vobj(u32 id) {
    return (id & VOBJ_MASK) == VOBJ_BASE && (id - VOBJ_BASE) < VOBJ_MAX;
}

static bool sd_dir_exists(const char* path) {
    if (!g_sd || !path || !path[0]) return false;
    u32 et = 0;
    return R_SUCCEEDED(nupRawFsGetEntryType(g_sd, path, &et)) && et == FsDirEntryType_Dir;
}

static void format_sd_subpath(const char* root, const char* rel, char* out, size_t out_sz) {
    const char* p = rel ? rel : "";
    while (*p == '/') p++;
    // Reject path traversal
    if (strstr(p, "..") != NULL) {
        snprintf(out, out_sz, "%s", root);
        return;
    }
    if (*p)
        snprintf(out, out_sz, "%s/%s", root, p);
    else
        snprintf(out, out_sz, "%s", root);
    size_t len = strlen(out);
    while (len > 1 && out[len - 1] == '/')
        out[--len] = '\0';
}

static void ensure_sd_dir_recursive(const char* path) {
    if (!g_sd || !path || path[0] != '/')
        return;
    char tmp[0x300];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            nupRawFsCreateDir(g_sd, tmp);
            *p = '/';
        }
    }
    nupRawFsCreateDir(g_sd, tmp);
}

// --- DLC discovery (unpacked SD folders) ---

static int parse_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_dlc_index(const char* name) {
    if (!name || !name[0]) return -1;
    bool all_dec = true;
    int dec_val = 0;
    for (const char* p = name; *p; p++) {
        if (*p < '0' || *p > '9') { all_dec = false; break; }
        dec_val = dec_val * 10 + (*p - '0');
    }
    if (all_dec && dec_val > 0 && dec_val < 0x1000)
        return dec_val;

    const size_t n = strlen(name);
    for (size_t i = 0; i + 16 <= n; i++) {
        u64 tid = 0;
        bool ok = true;
        for (size_t j = 0; j < 16; j++) {
            const int nib = parse_hex_nibble(name[i + j]);
            if (nib < 0) { ok = false; break; }
            tid = (tid << 4) | (u64)nib;
        }
        if (ok && (tid >> 48) != 0) {
            const int idx = (int)(tid & 0xFFFull);
            if (idx > 0) return idx;
        }
    }
    return -1;
}

static void add_dlc_slot(int idx, const char* sd_root) {
    for (int i = 0; i < g_dlc_count; i++) {
        if (g_dlcs[i].index == idx) return;
    }
    if (g_dlc_count >= MAX_DLC_SLOTS) return;
    DlcSlot* s = &g_dlcs[g_dlc_count++];
    memset(s, 0, sizeof(*s));
    s->index = idx;
    snprintf(s->sd_root, sizeof(s->sd_root), "%s", sd_root);
}

static void resolve_dlc_romfs_root(const char* sub, char* out, size_t out_sz) {
    char cand[0x300];
    format_sd_subpath(sub, "romfs", cand, sizeof(cand));
    if (sd_dir_exists(cand)) { snprintf(out, out_sz, "%s", cand); return; }
    format_sd_subpath(sub, "0/romfs", cand, sizeof(cand));
    if (sd_dir_exists(cand)) { snprintf(out, out_sz, "%s", cand); return; }
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
                    snprintf(out, out_sz, "%s", cand);
                    found = true;
                    break;
                }
            }
        }
        serviceClose(&d.s);
        if (found) return;
    }
    snprintf(out, out_sz, "%s", sub);
}

static void scan_dlc_parent(const char* parent) {
    if (!g_sd || !sd_dir_exists(parent)) return;
    char direct_romfs[0x300];
    format_sd_subpath(parent, "romfs", direct_romfs, sizeof(direct_romfs));
    if (sd_dir_exists(direct_romfs)) {
        add_dlc_slot(1, direct_romfs);
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
            if (idx <= 0) continue;
            char sub[0x300], romsub[0x300];
            format_sd_subpath(parent, ents[i].name, sub, sizeof(sub));
            resolve_dlc_romfs_root(sub, romsub, sizeof(romsub));
            add_dlc_slot(idx, romsub);
        }
    }
    serviceClose(&d.s);
}

static void sort_dlcs(void) {
    for (int i = 1; i < g_dlc_count; i++) {
        DlcSlot key = g_dlcs[i];
        int j = i - 1;
        while (j >= 0 && g_dlcs[j].index > key.index) {
            g_dlcs[j + 1] = g_dlcs[j];
            j--;
        }
        g_dlcs[j + 1] = key;
    }
}

// --- Session & virtual object tables ---

static void session_register(Handle h, TrackedSessionKind kind) {
    if (!h || h == INVALID_HANDLE) return;
    nupSpinLock(&g_svc_lock);
    int empty = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].handle == h) {
            g_sessions[i].kind = kind;
            g_sessions[i].is_domain = false;
            nupSpinUnlock(&g_svc_lock);
            return;
        }
        if (empty < 0 && g_sessions[i].kind == SESS_NONE)
            empty = i;
    }
    if (empty >= 0) {
        g_sessions[empty].handle = h;
        g_sessions[empty].kind = kind;
        g_sessions[empty].is_domain = false;
    }
    nupSpinUnlock(&g_svc_lock);
}

static TrackedSession* session_find_locked(Handle h) {
    if (!h || h == INVALID_HANDLE) return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].kind != SESS_NONE && g_sessions[i].handle == h)
            return &g_sessions[i];
    }
    return NULL;
}

static void session_forget(Handle h) {
    if (!h || h == INVALID_HANDLE) return;
    nupSpinLock(&g_svc_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].handle == h) {
            g_sessions[i].handle = 0;
            g_sessions[i].kind = SESS_NONE;
            g_sessions[i].is_domain = false;
            break;
        }
    }
    nupSpinUnlock(&g_svc_lock);
}

static u32 vobj_alloc(const VirtualObj* init) {
    nupSpinLock(&g_svc_lock);
    for (u32 i = 0; i < VOBJ_MAX; i++) {
        if (g_vobjs[i].kind == VOBJ_NONE) {
            g_vobjs[i] = *init;
            nupSpinUnlock(&g_svc_lock);
            return VOBJ_BASE + i;
        }
    }
    nupSpinUnlock(&g_svc_lock);
    return 0;
}

static void vobj_free_inner(VirtualObj* o) {
    if (o->kind == VOBJ_FILE)
        serviceClose(&o->file.s);
    else if (o->kind == VOBJ_DIR)
        serviceClose(&o->dir.s);
    memset(o, 0, sizeof(*o));
}

static void vobj_free(u32 id) {
    if (!is_vobj(id)) return;
    nupSpinLock(&g_svc_lock);
    VirtualObj* o = &g_vobjs[id - VOBJ_BASE];
    if (o->kind != VOBJ_NONE)
        vobj_free_inner(o);
    nupSpinUnlock(&g_svc_lock);
}

static Handle vhandle_alloc(const VirtualObj* init) {
    nupSpinLock(&g_svc_lock);
    for (u32 i = 0; i < VHANDLE_MAX; i++) {
        if (g_vhandles[i].kind == VOBJ_NONE) {
            g_vhandles[i] = *init;
            nupSpinUnlock(&g_svc_lock);
            return VHANDLE_BASE + i;
        }
    }
    nupSpinUnlock(&g_svc_lock);
    return INVALID_HANDLE;
}

static void vhandle_free(Handle h) {
    if (!is_vhandle(h)) return;
    nupSpinLock(&g_svc_lock);
    VirtualObj* o = &g_vhandles[h - VHANDLE_BASE];
    if (o->kind != VOBJ_NONE)
        vobj_free_inner(o);
    nupSpinUnlock(&g_svc_lock);
}

// --- Lazy virtual RomFS builders ---

static bool mount_romfs_via_plugin(VfsRomfs* dst, const char* rom_root,
                                   const char* const* overlays, int ov_cnt, int prog_idx) {
    if (!g_vfs_plugin_ok || !rom_root || !rom_root[0])
        return false;
    char packed[NUPVFS_MAX_LAYERS * NUPVFS_PATH_MAX];
    size_t pos = 0;
    u32 count = 0;

    const size_t rlen = strlen(rom_root);
    if (rlen == 0 || rlen + 1 >= sizeof(packed))
        return false;
    memcpy(packed + pos, rom_root, rlen + 1);
    pos += rlen + 1;
    count++;

    for (int i = 0; i < ov_cnt && count < NUPVFS_MAX_LAYERS; i++) {
        if (!overlays[i] || !overlays[i][0])
            continue;
        const size_t olen = strlen(overlays[i]);
        if (pos + olen + 1 >= sizeof(packed))
            break;
        memcpy(packed + pos, overlays[i], olen + 1);
        pos += olen + 1;
        count++;
    }

    const NupVfsMountReq req = {
        .title_id = g_title_id,
        .prog_idx = (u32)(prog_idx >= 0 ? prog_idx : 0),
        .num_layers = count,
    };
    NupVfsMountReply rep = {};
    nupSpinLock(&g_vfs_ipc_lock);
    const Result rc = serviceDispatchInOut(&g_vfs_plugin, NupVfsCmd_MountRomfs, req, rep,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers = {{ packed, pos }});
    nupSpinUnlock(&g_vfs_ipc_lock);
    if (R_FAILED(rc) || rep.slot_id == 0)
        return false;

    memset(dst, 0, sizeof(*dst));
    dst->ready = true;
    dst->remote_slot = rep.slot_id;
    dst->total_size = rep.total_size;
    nupLogf("[svc-vfs] nupvfs.nso MountRomfs OK (slot=%u %s size=0x%llx root='%s')\n",
            rep.slot_id, rep.cached ? "CACHED" : "BUILT",
            (unsigned long long)rep.total_size, rom_root);
    return true;
}

static void build_romfs_with_mods(VfsRomfs* dst, const char* rom_root,
                                  const char* upd_overlay, int prog_idx) {
    char mod1[0x300] = {}, mod2[0x300] = {};
    const char* overlays[4];
    int ov_cnt = 0;
    if (upd_overlay && upd_overlay[0])
        overlays[ov_cnt++] = upd_overlay;
    if (g_title_id && (g_vfs_flags & NUPVFS_FLAG_MODS)) {
        if (prog_idx > 0) {
            snprintf(mod1, sizeof(mod1), "/kaihen/mods/%016llx/program%d/romfs",
                     (unsigned long long)g_title_id, prog_idx);
            if (sd_dir_exists(mod1)) overlays[ov_cnt++] = mod1;
        }
        snprintf(mod2, sizeof(mod2), "/kaihen/mods/%016llx/romfs",
                 (unsigned long long)g_title_id);
        if (sd_dir_exists(mod2)) overlays[ov_cnt++] = mod2;
    }
    if (mount_romfs_via_plugin(dst, rom_root, overlays, ov_cnt, prog_idx))
        return;
    vfsRomfsBuildLayered(dst, g_sd, rom_root, overlays, ov_cnt);
}

static VfsRomfs* get_active_romfs(void) {
    nupSpinLock(&g_svc_lock);
    if (!g_active_romfs_built) {
        g_active_romfs_built = true;
        if (g_nup && g_nup->raw_root[0]) {
            char rom_root[0x300];
            if (g_nup->raw_romfs_root[0])
                snprintf(rom_root, sizeof(rom_root), "%s", g_nup->raw_romfs_root);
            else
                format_sd_subpath(g_nup->raw_root, "romfs", rom_root, sizeof(rom_root));
            nupSpinUnlock(&g_svc_lock);
            build_romfs_with_mods(&g_active_romfs, rom_root,
                                  g_has_rom_overlay ? g_rom_overlay_root : NULL,
                                  g_nup->raw_is_subprogram ? 1 : 0);
            return g_active_romfs.ready ? &g_active_romfs : NULL;
        }
    }
    nupSpinUnlock(&g_svc_lock);
    return g_active_romfs.ready ? &g_active_romfs : NULL;
}

static VfsRomfs* get_program_romfs(u32 prog_idx) {
    if (prog_idx >= MAX_PROG_ROMS || !g_nup)
        return get_active_romfs();
    nupSpinLock(&g_svc_lock);
    if (!g_prog_romfs_built[prog_idx]) {
        g_prog_romfs_built[prog_idx] = true;
        const char* app_root = g_nup->raw_app_root[0] ? g_nup->raw_app_root : g_nup->raw_root;
        char game_dir[0x300];
        format_sd_subpath(app_root, "game", game_dir, sizeof(game_dir));
        const char* base = sd_dir_exists(game_dir) ? game_dir : app_root;
        char rom_root[0x300];
        if (prog_idx == 0) {
            format_sd_subpath(base, "romfs", rom_root, sizeof(rom_root));
        } else {
            char sub[32];
            snprintf(sub, sizeof(sub), "program%u/romfs", prog_idx);
            format_sd_subpath(base, sub, rom_root, sizeof(rom_root));
        }
        const bool same_active = (g_nup->raw_romfs_root[0] && strcmp(rom_root, g_nup->raw_romfs_root) == 0);
        nupSpinUnlock(&g_svc_lock);
        if (same_active)
            return get_active_romfs();
        if (sd_dir_exists(rom_root)) {
            build_romfs_with_mods(&g_prog_romfs[prog_idx], rom_root,
                                  NULL,
                                  (int)prog_idx);
        }
        return g_prog_romfs[prog_idx].ready ? &g_prog_romfs[prog_idx] : get_active_romfs();
    }
    nupSpinUnlock(&g_svc_lock);
    return g_prog_romfs[prog_idx].ready ? &g_prog_romfs[prog_idx] : get_active_romfs();
}

static VfsRomfs* get_dlc_romfs(int dlc_idx) {
    for (int i = 0; i < g_dlc_count; i++) {
        if (g_dlcs[i].index == dlc_idx) {
            nupSpinLock(&g_svc_lock);
            if (!g_dlcs[i].romfs_built) {
                g_dlcs[i].romfs_built = true;
                nupSpinUnlock(&g_svc_lock);
                vfsRomfsBuild(&g_dlcs[i].romfs, g_sd, g_dlcs[i].sd_root, NULL);
            } else {
                nupSpinUnlock(&g_svc_lock);
            }
            return g_dlcs[i].romfs.ready ? &g_dlcs[i].romfs : NULL;
        }
    }
    return NULL;
}

// --- Horizon HIPC / CMIF / TIPC parser & reply writers ---

typedef struct {
    u64 addr;
    u64 size;
} IpcBuf;

typedef struct {
    u32 type;
    bool is_tipc;
    bool is_domain;
    u8 domain_cmd;
    u32 domain_obj;
    u32 cmd;
    const u8* raw_in;
    u32 raw_in_bytes;
    IpcBuf x_bufs[4];
    u32 num_x;
    IpcBuf a_bufs[4];
    u32 num_a;
    IpcBuf b_bufs[4];
    u32 num_b;
    IpcBuf c_bufs[4];
    u32 num_c;
} ParsedIpc;

static bool parse_ipc_request(const u8* m, bool session_is_domain, ParsedIpc* out) {
    memset(out, 0, sizeof(*out));
    const u32 w0 = rd32(m + 0);
    const u32 w1 = rd32(m + 4);
    out->type = w0 & 0xFFFFu;
    out->is_tipc = (out->type >= 16u);

    const u32 num_x = (w0 >> 16) & 0xFu;
    const u32 num_a = (w0 >> 20) & 0xFu;
    const u32 num_b = (w0 >> 24) & 0xFu;
    const u32 num_w = (w0 >> 28) & 0xFu;
    const u32 raw_words = w1 & 0x3FFu;
    const u32 c_flags = (w1 >> 10) & 0xFu;
    const bool has_special = ((w1 >> 31) & 1u) != 0;

    u32 off = 8;
    if (has_special) {
        if (off + 4 > 0x100) return false;
        const u32 sp = rd32(m + off);
        off += 4;
        if (sp & 1u) off += 8; // send_pid
        const u32 n_copy = (sp >> 1) & 0xFu;
        const u32 n_move = (sp >> 5) & 0xFu;
        off += 4u * (n_copy + n_move);
    }

    for (u32 i = 0; i < num_x; i++) {
        if (off + 8 > 0x100) return false;
        const u32 x0 = rd32(m + off);
        const u32 x1 = rd32(m + off + 4);
        off += 8;
        if (out->num_x < 4) {
            out->x_bufs[out->num_x].addr = (u64)x1 | (((u64)((x0 >> 12) & 0xFu)) << 32) | (((u64)((x0 >> 6) & 0x7u)) << 36);
            out->x_bufs[out->num_x].size = (u64)(x0 >> 16);
            out->num_x++;
        }
    }
    for (u32 i = 0; i < num_a; i++) {
        if (off + 12 > 0x100) return false;
        const u32 d0 = rd32(m + off), d1 = rd32(m + off + 4), d2 = rd32(m + off + 8);
        off += 12;
        if (out->num_a < 4) {
            out->a_bufs[out->num_a].addr = (u64)d1 | (((u64)((d2 >> 28) & 0xFu)) << 32) | (((u64)((d2 >> 2) & 0x7u)) << 36);
            out->a_bufs[out->num_a].size = (u64)d0 | (((u64)((d2 >> 24) & 0xFu)) << 32);
            out->num_a++;
        }
    }
    for (u32 i = 0; i < num_b; i++) {
        if (off + 12 > 0x100) return false;
        const u32 d0 = rd32(m + off), d1 = rd32(m + off + 4), d2 = rd32(m + off + 8);
        off += 12;
        if (out->num_b < 4) {
            out->b_bufs[out->num_b].addr = (u64)d1 | (((u64)((d2 >> 28) & 0xFu)) << 32) | (((u64)((d2 >> 2) & 0x7u)) << 36);
            out->b_bufs[out->num_b].size = (u64)d0 | (((u64)((d2 >> 24) & 0xFu)) << 32);
            out->num_b++;
        }
    }
    off += num_w * 12u;
    if (off > 0x100) return false;

    const u32 raw_end = off + raw_words * 4u;
    if (c_flags >= 2 && raw_end < 0x100) {
        const u32 nc = (c_flags == 2) ? 1u : (c_flags == 3 ? 1u : (c_flags - 2u));
        u32 coff = raw_end;
        for (u32 i = 0; i < nc && coff + 8 <= 0x100; i++) {
            const u32 c0 = rd32(m + coff), c1 = rd32(m + coff + 4);
            coff += 8;
            if (out->num_c < 4) {
                out->c_bufs[out->num_c].addr = (u64)c0 | (((u64)(c1 & 0xFFFFu)) << 32);
                out->c_bufs[out->num_c].size = (u64)(c1 >> 16);
                out->num_c++;
            }
        }
    }

    if (out->is_tipc) {
        out->cmd = out->type - 16u;
        out->raw_in = m + off;
        out->raw_in_bytes = (raw_words * 4u <= 0x100 - off) ? raw_words * 4u : (0x100 - off);
        return true;
    }

    const u32 aligned = (off + 15u) & ~15u;
    if (aligned + 16u > 0x100) return false;

    // Control messages (5, 7) are never domain-wrapped
    if (out->type == 5u || out->type == 7u) {
        if (rd32(m + aligned) != 0x49434653u) return false; // "SFCI"
        out->cmd = rd32(m + aligned + 8);
        out->raw_in = m + aligned + 16;
        out->raw_in_bytes = (0x100 > aligned + 16) ? (0x100 - (aligned + 16)) : 0;
        return true;
    }

    if (out->type != 4u && out->type != 6u)
        return false;

    if (session_is_domain || (rd32(m + aligned) != 0x49434653u && aligned + 32u <= 0x100 &&
                              (m[aligned] == 1u || m[aligned] == 2u))) {
        out->is_domain = true;
        out->domain_cmd = m[aligned];
        out->domain_obj = rd32(m + aligned + 4);
        if (out->domain_cmd == 2u)
            return true;
        if (aligned + 32u > 0x100 || rd32(m + aligned + 16) != 0x49434653u)
            return false;
        out->cmd = rd32(m + aligned + 24);
        out->raw_in = m + aligned + 32;
        out->raw_in_bytes = (0x100 > aligned + 32) ? (0x100 - (aligned + 32)) : 0;
        return true;
    }

    if (rd32(m + aligned) != 0x49434653u)
        return false;
    out->cmd = rd32(m + aligned + 8);
    out->raw_in = m + aligned + 16;
    out->raw_in_bytes = (0x100 > aligned + 16) ? (0x100 - (aligned + 16)) : 0;
    return true;
}

static void write_cmif_reply(u8* m, bool is_domain, u32 result,
                             const void* raw_out, u32 raw_out_sz,
                             u32 domain_out_obj, Handle move_h, Handle copy_h) {
    memset(m, 0, 0x100);
    const bool has_h = (move_h != INVALID_HANDLE) || (copy_h != INVALID_HANDLE);
    u32 off = 8;
    if (has_h) {
        u32 sp = 0;
        if (copy_h != INVALID_HANDLE) sp |= (1u << 1);
        if (move_h != INVALID_HANDLE) sp |= (1u << 5);
        wr32(m + off, sp);
        off += 4;
        if (copy_h != INVALID_HANDLE) { wr32(m + off, copy_h); off += 4; }
        if (move_h != INVALID_HANDLE) { wr32(m + off, move_h); off += 4; }
    }
    const u32 hdr_end = off;
    const u32 aligned = (hdr_end + 15u) & ~15u;
    u8* p = m + aligned;
    if (is_domain) {
        wr32(p + 0, domain_out_obj ? 1u : 0u);
        p += 16;
    }
    wr32(p + 0, 0x4F434653u); // "SFCO"
    wr32(p + 8, result);
    p += 16;
    if (raw_out && raw_out_sz) {
        memcpy(p, raw_out, raw_out_sz);
        p += raw_out_sz;
    }
    if (is_domain && domain_out_obj) {
        wr32(p, domain_out_obj);
        p += 4;
    }
    // Horizon raw_data_size in words includes pre-alignment + trailing 16-byte padding slack
    const u32 total_bytes = (u32)(p - (m + hdr_end));
    const u32 data_words = (total_bytes + 16u + 3u) / 4u;
    wr32(m + 4, (has_h ? 0x80000000u : 0u) | (data_words & 0x3FFu));
}

static void write_tipc_reply(u8* m, u32 result, Handle move_h) {
    memset(m, 0, 0x100);
    if (move_h != INVALID_HANDLE) {
        wr32(m + 4, 0x80000000u | 1u);
        wr32(m + 8, 1u << 5);
        wr32(m + 12, move_h);
        wr32(m + 16, result);
    } else {
        wr32(m + 4, 1u);
        wr32(m + 8, result);
    }
}

static bool extract_reply_info(const u8* m, bool is_tipc, u32* out_result, Handle* out_handle) {
    *out_result = 0;
    *out_handle = INVALID_HANDLE;
    const u32 w1 = rd32(m + 4);
    const bool has_special = ((w1 >> 31) & 1u) != 0;
    u32 off = 8;
    if (has_special) {
        const u32 sp = rd32(m + off);
        off += 4;
        if (sp & 1u) off += 8;
        const u32 n_copy = (sp >> 1) & 0xFu;
        const u32 n_move = (sp >> 5) & 0xFu;
        if (n_copy + n_move > 0 && off + 4 <= 0x100)
            *out_handle = rd32(m + off);
        off += 4u * (n_copy + n_move);
    }
    if (is_tipc) {
        if (off + 4 <= 0x100)
            *out_result = rd32(m + off);
        return true;
    }
    const u32 aligned = (off + 15u) & ~15u;
    if (aligned + 16 <= 0x100 && rd32(m + aligned) == 0x4F434653u) {
        *out_result = rd32(m + aligned + 8);
        return true;
    }
    if (aligned + 32 <= 0x100 && rd32(m + aligned + 16) == 0x4F434653u) {
        *out_result = rd32(m + aligned + 24);
        return true;
    }
    return false;
}

static bool read_ipc_path(const ParsedIpc* req, u32 idx, char* out, size_t out_sz) {
    out[0] = '\0';
    if (idx < req->num_x && req->x_bufs[idx].addr && req->x_bufs[idx].size > 0) {
        const size_t n = req->x_bufs[idx].size < out_sz - 1 ? (size_t)req->x_bufs[idx].size : out_sz - 1;
        memcpy(out, (const void*)(uintptr_t)req->x_bufs[idx].addr, n);
        out[n] = '\0';
        return true;
    }
    if (idx < req->num_a && req->a_bufs[idx].addr && req->a_bufs[idx].size > 0) {
        const size_t n = req->a_bufs[idx].size < out_sz - 1 ? (size_t)req->a_bufs[idx].size : out_sz - 1;
        memcpy(out, (const void*)(uintptr_t)req->a_bufs[idx].addr, n);
        out[n] = '\0';
        return true;
    }
    return false;
}

// --- Virtual Object IPC handlers (IStorage, IFileSystem, IFile, IDirectory) ---

static bool handle_vobj_ipc(VirtualObj* obj, u8* m, const ParsedIpc* req) {
    const bool dom = req->is_domain;
    if (obj->kind == VOBJ_STORAGE) {
        if (req->cmd == 0) { // Read(s64 offset, u64 size) -> B-buf
            const u64 offset = rd64(req->raw_in + 0);
            const u64 size = rd64(req->raw_in + 8);
            if (req->num_b == 0 || !req->b_bufs[0].addr) {
                write_cmif_reply(m, dom, FS_RC_INVALID_ARG, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            const u64 want = size < req->b_bufs[0].size ? size : req->b_bufs[0].size;
            u64 got = 0;
            Result rc = 0;
            if (obj->romfs && obj->romfs->remote_slot != 0 && g_vfs_plugin_ok) {
                u8* dst_ptr = (u8*)(uintptr_t)req->b_bufs[0].addr;
                u64 done = 0;
                while (done < want) {
                    const u64 chunk = (want - done) > 0x400000ull ? 0x400000ull : (want - done);
                    const NupVfsReadReq rreq = {
                        .slot_id = obj->romfs->remote_slot,
                        .pad = 0,
                        .offset = offset + done,
                        .size = chunk,
                    };
                    u64 cgot = 0;
                    nupSpinLock(&g_vfs_ipc_lock);
                    rc = serviceDispatchInOut(&g_vfs_plugin, NupVfsCmd_ReadRomfs, rreq, cgot,
                        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
                        .buffers = {{ dst_ptr + done, (size_t)chunk }});
                    nupSpinUnlock(&g_vfs_ipc_lock);
                    if (R_FAILED(rc))
                        break;
                    done += cgot;
                    if (cgot < chunk)
                        break;
                }
                got = done;
            } else {
                rc = vfsRomfsRead(obj->romfs, offset, (void*)(uintptr_t)req->b_bufs[0].addr, want, &got);
            }
            (void)got;
            write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        if (req->cmd == 1 || req->cmd == 3) { // Write / SetSize
            write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        if (req->cmd == 2) { // Flush
            write_cmif_reply(m, dom, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        if (req->cmd == 4) { // GetSize
            const s64 sz = (s64)vfsRomfsSize(obj->romfs);
            write_cmif_reply(m, dom, 0, &sz, sizeof(sz), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        if (req->cmd == 5) { // OperateRange
            u8 info[0x40] = {};
            write_cmif_reply(m, dom, 0, info, sizeof(info), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        return true;
    }

    if (obj->kind == VOBJ_FS) {
        char rel1[FS_MAX_PATH], rel2[FS_MAX_PATH], sd1[FS_MAX_PATH], sd2[FS_MAX_PATH];
        switch (req->cmd) {
        case 0: { // CreateFile(u32 opt, u32 pad, s64 size)
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            const u32 opt = rd32(req->raw_in + 0);
            const s64 sz = (s64)rd64(req->raw_in + 8);
            const Result rc = nupRawFsCreateFile(g_sd, sd1, sz, opt);
            write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 1: { // DeleteFile
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            write_cmif_reply(m, dom, nupRawFsDeleteFile(g_sd, sd1), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 2: { // CreateDirectory
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            write_cmif_reply(m, dom, nupRawFsCreateDir(g_sd, sd1), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 3: { // DeleteDirectory
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            write_cmif_reply(m, dom, nupRawFsDeleteDir(g_sd, sd1), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 4: { // DeleteDirectoryRecursively
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            write_cmif_reply(m, dom, nupRawFsDeleteDirRec(g_sd, sd1), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 5: { // RenameFile
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            read_ipc_path(req, 1, rel2, sizeof(rel2));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            format_sd_subpath(obj->sd_root, rel2, sd2, sizeof(sd2));
            write_cmif_reply(m, dom, nupRawFsRenameFile(g_sd, sd1, sd2), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 6: { // RenameDirectory
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            read_ipc_path(req, 1, rel2, sizeof(rel2));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            format_sd_subpath(obj->sd_root, rel2, sd2, sizeof(sd2));
            write_cmif_reply(m, dom, nupRawFsRenameDir(g_sd, sd1, sd2), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 7: { // GetEntryType
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            u32 et = 0;
            const Result rc = nupRawFsGetEntryType(g_sd, sd1, &et);
            write_cmif_reply(m, dom, rc, &et, sizeof(et), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 8: { // OpenFile(u32 mode) -> IFile
            u32 mode = rd32(req->raw_in + 0);
            if (obj->read_only && (mode & (FsOpenMode_Write | FsOpenMode_Append))) {
                write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            const u32 sd_mode = obj->read_only ? FsOpenMode_Read
                                               : (mode & (FsOpenMode_Read | FsOpenMode_Write | FsOpenMode_Append));
            FsFile f = {};
            const Result rc = nupRawFsOpenFile(g_sd, sd1, sd_mode ? sd_mode : FsOpenMode_Read, &f);
            if (R_FAILED(rc)) {
                write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            s64 sz = 0;
            nupRawFileGetSize(&f, &sz);
            VirtualObj vo = {};
            vo.kind = VOBJ_FILE;
            vo.read_only = obj->read_only;
            vo.file = f;
            vo.cached_size = sz;
            if (dom) {
                const u32 oid = vobj_alloc(&vo);
                if (!oid) { serviceClose(&f.s); write_cmif_reply(m, dom, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
                write_cmif_reply(m, true, 0, NULL, 0, oid, INVALID_HANDLE, INVALID_HANDLE);
            } else {
                const Handle vh = vhandle_alloc(&vo);
                if (vh == INVALID_HANDLE) { serviceClose(&f.s); write_cmif_reply(m, false, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
                write_cmif_reply(m, false, 0, NULL, 0, 0, vh, INVALID_HANDLE);
            }
            return true;
        }
        case 9: { // OpenDirectory(u32 mode) -> IDirectory
            const u32 mode = rd32(req->raw_in + 0);
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            FsDir d = {};
            const Result rc = nupRawFsOpenDir(g_sd, sd1, mode, &d);
            if (R_FAILED(rc)) {
                write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            VirtualObj vo = {};
            vo.kind = VOBJ_DIR;
            vo.dir = d;
            if (dom) {
                const u32 oid = vobj_alloc(&vo);
                if (!oid) { serviceClose(&d.s); write_cmif_reply(m, dom, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
                write_cmif_reply(m, true, 0, NULL, 0, oid, INVALID_HANDLE, INVALID_HANDLE);
            } else {
                const Handle vh = vhandle_alloc(&vo);
                if (vh == INVALID_HANDLE) { serviceClose(&d.s); write_cmif_reply(m, false, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
                write_cmif_reply(m, false, 0, NULL, 0, 0, vh, INVALID_HANDLE);
            }
            return true;
        }
        case 10: { // Commit
            if (!obj->read_only) nupRawFsCommit(g_sd);
            write_cmif_reply(m, dom, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 11: { // GetFreeSpaceSize
            s64 sz = 0x40000000ll;
            nupRawFsGetFreeSpace(g_sd, obj->sd_root, &sz);
            write_cmif_reply(m, dom, 0, &sz, sizeof(sz), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 12: { // GetTotalSpaceSize
            s64 sz = 0x80000000ll;
            nupRawFsGetTotalSpace(g_sd, obj->sd_root, &sz);
            write_cmif_reply(m, dom, 0, &sz, sizeof(sz), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 13: { // CleanDirectoryRecursively
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            read_ipc_path(req, 0, rel1, sizeof(rel1));
            format_sd_subpath(obj->sd_root, rel1, sd1, sizeof(sd1));
            write_cmif_reply(m, dom, nupRawFsCleanDirRec(g_sd, sd1), NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 14: { // GetFileTimeStampRaw
            u8 ts[0x20] = {};
            ts[0x18] = 1; // is_valid
            write_cmif_reply(m, dom, 0, ts, sizeof(ts), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 16: { // GetFileSystemAttribute (HOS 15.0+)
            u8 attr[0xC0] = {};
            const Result rc = serviceDispatchOut(&g_sd->s, 16, attr);
            write_cmif_reply(m, dom, rc, attr, sizeof(attr), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        default:
            write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
    }

    if (obj->kind == VOBJ_FILE) {
        switch (req->cmd) {
        case 0: { // Read(u32 opt, u32 pad, s64 off, u64 size) -> B-buf, out u64 got
            const s64 off = (s64)rd64(req->raw_in + 8);
            const u64 sz = rd64(req->raw_in + 16);
            if (req->num_b == 0 || !req->b_bufs[0].addr) {
                write_cmif_reply(m, dom, FS_RC_INVALID_ARG, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            const u64 want = sz < req->b_bufs[0].size ? sz : req->b_bufs[0].size;
            u64 total = 0;
            Result rc = 0;
            while (total < want) {
                const u64 chunk = (want - total) > 0x400000ull ? 0x400000ull : (want - total);
                u64 got = 0;
                rc = nupRawFileRead(&obj->file, off + (s64)total, (u8*)(uintptr_t)req->b_bufs[0].addr + total, chunk, &got);
                if (R_FAILED(rc)) break;
                total += got;
                if (got < chunk) break;
            }
            write_cmif_reply(m, dom, rc, &total, sizeof(total), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 1: { // Write(u32 opt, u32 pad, s64 off, u64 size) <- A-buf
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            const u32 opt = rd32(req->raw_in + 0);
            const s64 off = (s64)rd64(req->raw_in + 8);
            const u64 sz = rd64(req->raw_in + 16);
            if (sz == 0) {
                const Result rc = (opt & FsWriteOption_Flush) ? nupRawFileFlush(&obj->file) : 0;
                write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            if (req->num_a == 0 || !req->a_bufs[0].addr) {
                write_cmif_reply(m, dom, FS_RC_INVALID_ARG, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            const u64 want = sz < req->a_bufs[0].size ? sz : req->a_bufs[0].size;
            u64 total = 0;
            Result rc = 0;
            while (total < want) {
                const u64 chunk = (want - total) > 0x400000ull ? 0x400000ull : (want - total);
                const u32 copt = (total + chunk >= want) ? opt : FsWriteOption_None;
                rc = nupRawFileWrite(&obj->file, off + (s64)total, (const u8*)(uintptr_t)req->a_bufs[0].addr + total, chunk, copt);
                if (R_FAILED(rc)) break;
                total += chunk;
            }
            write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 2: { // Flush
            const Result rc = obj->read_only ? 0 : nupRawFileFlush(&obj->file);
            write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 3: { // SetSize(s64 size)
            if (obj->read_only) { write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE); return true; }
            const s64 sz = (s64)rd64(req->raw_in + 0);
            const Result rc = nupRawFileSetSize(&obj->file, sz);
            if (R_SUCCEEDED(rc)) obj->cached_size = sz;
            write_cmif_reply(m, dom, rc, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 4: { // GetSize
            s64 sz = obj->cached_size;
            const Result rc = nupRawFileGetSize(&obj->file, &sz);
            write_cmif_reply(m, dom, rc, &sz, sizeof(sz), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        case 5: { // OperateRange
            u8 info[0x40] = {};
            write_cmif_reply(m, dom, 0, info, sizeof(info), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        default:
            write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
    }

    if (obj->kind == VOBJ_DIR) {
        if (req->cmd == 0) { // Read -> B-buf FsDirectoryEntry[], out s64 count
            if (req->num_b == 0 || !req->b_bufs[0].addr) {
                write_cmif_reply(m, dom, FS_RC_INVALID_ARG, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            const u64 max_cnt = req->b_bufs[0].size / sizeof(FsDirectoryEntry);
            s64 got = 0;
            const Result rc = nupRawDirRead(&obj->dir, &got, (FsDirectoryEntry*)(uintptr_t)req->b_bufs[0].addr, max_cnt);
            write_cmif_reply(m, dom, rc, &got, sizeof(got), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        if (req->cmd == 1) { // GetEntryCount
            s64 cnt = 0;
            const Result rc = nupRawDirGetEntryCount(&obj->dir, &cnt);
            write_cmif_reply(m, dom, rc, &cnt, sizeof(cnt), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        return true;
    }

    if (obj->kind == VOBJ_SAVE_READER) {
        if (req->cmd == 0) { // ReadSaveDataInfo -> B-buf FsSaveDataInfo (0x60 bytes each), out s64 count
            if (req->num_b == 0 || !req->b_bufs[0].addr) {
                write_cmif_reply(m, dom, FS_RC_INVALID_ARG, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            const u64 max_cnt = req->b_bufs[0].size / sizeof(FsSaveDataInfo);
            FsSaveDataInfo* out_info = (FsSaveDataInfo*)(uintptr_t)req->b_bufs[0].addr;
            s64 written = 0;
            if (obj->reader_pos == 0 && max_cnt > 0 && g_title_id) {
                // Report existing SD-backed save directories (user, device, cache_0..7)
                static const struct { const char* sub; u8 type; u16 idx; } probes[] = {
                    { "user",    1, 0 },
                    { "device",  3, 0 },
                    { "bcat",    2, 0 },
                    { "cache_0", 5, 0 },
                    { "cache_1", 5, 1 },
                    { "cache_2", 5, 2 },
                    { "cache_3", 5, 3 },
                };
                for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]) && (u64)written < max_cnt; i++) {
                    char p[0x300];
                    snprintf(p, sizeof(p), "/kaihen/saves/%016llx/%s",
                             (unsigned long long)g_title_id, probes[i].sub);
                    if (!sd_dir_exists(p))
                        continue;
                    memset(&out_info[written], 0, sizeof(FsSaveDataInfo));
                    out_info[written].save_data_id = 0x1000000000000000ull + (u64)i + 1ull;
                    out_info[written].save_data_space_id = 1; // User
                    out_info[written].save_data_type = probes[i].type;
                    out_info[written].application_id = g_title_id;
                    out_info[written].size = 0x4000000ull; // 64 MiB
                    out_info[written].save_data_index = probes[i].idx;
                    written++;
                }
                obj->reader_pos = 1;
            }
            write_cmif_reply(m, dom, 0, &written, sizeof(written), 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        write_cmif_reply(m, dom, FS_RC_UNSUPPORTED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        return true;
    }

    if (obj->kind == VOBJ_STANDIN) {
        if (req->type == 5u || req->type == 7u) { // Control commands on virtual stand-in session
            if (req->cmd == 0u) { // ConvertCurrentObjectToDomain
                obj->is_domain = true;
                const u32 root_id = 0x100u;
                write_cmif_reply(m, false, 0, &root_id, sizeof(root_id), 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            if (req->cmd == 3u) { // QueryPointerBufferSize
                const u16 psz = 0xFFFFu;
                write_cmif_reply(m, false, 0, &psz, sizeof(psz), 0, INVALID_HANDLE, INVALID_HANDLE);
                return true;
            }
            if (req->cmd == 1u || req->cmd == 2u || req->cmd == 4u) { // Clone
                VirtualObj dup = *obj;
                const Handle nh = vhandle_alloc(&dup);
                write_cmif_reply(m, false, nh != INVALID_HANDLE ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                                 NULL, 0, 0, nh, INVALID_HANDLE);
                return true;
            }
            write_cmif_reply(m, false, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        if (req->is_domain && req->domain_cmd == 2u) { // CloseVirtualHandle
            write_cmif_reply(m, true, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            return true;
        }
        // Benign empty reply: zero-fill any B/C out buffers, return rc=0
        for (u32 i = 0; i < req->num_b; i++) {
            if (req->b_bufs[i].addr && req->b_bufs[i].size && req->b_bufs[i].size <= 0x10000ull)
                memset((void*)(uintptr_t)req->b_bufs[i].addr, 0, (size_t)req->b_bufs[i].size);
        }
        const bool is_dom = obj->is_domain || req->is_domain;
        const u32 out_obj = (is_dom && req->num_b == 0 && req->num_c == 0) ? 0x200u : 0u;
        write_cmif_reply(m, is_dom, 0, NULL, 0, out_obj, INVALID_HANDLE, INVALID_HANDLE);
        return true;
    }

    return false;
}

// --- Service-specific IPC handlers ---

static bool is_core_service(const char* name) {
    static const char* const core[] = {
        "nv", "vi:", "dispdrv", "gsv", "hid", "fsp", "applet",
        "aud", "ldr", "ro:", "sm:", "lm", "apm", "set", "time", "pl:", "acc"
    };
    for (size_t i = 0; i < sizeof(core) / sizeof(core[0]); i++) {
        if (strncmp(name, core[i], strlen(core[i])) == 0)
            return true;
    }
    return false;
}

static bool handle_sm_ipc(u64* regs, Handle h, u8* m, const u8* req_buf, bool with_user_buf, u64 ubuf_sz) {
    ParsedIpc req;
    if (!parse_ipc_request(req_buf, false, &req))
        return false;
    // sm: GetService is CMIF cmd 1 or TIPC type 17 (cmd 1)
    if (req.cmd != 1u || req.raw_in_bytes < 8)
        return false;

    char svc_name[9] = {};
    memcpy(svc_name, req.raw_in, 8);
    if (!svc_name[0])
        return false;

    // 1. Pre-opened GSV nvdrv delegation (Switch 1 compatibility)
    if (strcmp(svc_name, "nvdrv") == 0 && g_preopened_nv != INVALID_HANDLE) {
        Handle nh = g_preopened_nv;
        g_preopened_nv = INVALID_HANDLE;
        nupLogf("[svc-sm] GetService('nvdrv') -> delegated GSV handle 0x%x\n", nh);
        if (req.is_tipc) write_tipc_reply(m, 0, nh);
        else write_cmif_reply(m, false, 0, NULL, 0, 0, nh, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }

    Result krc = with_user_buf ? svcSendSyncRequestWithUserBuffer(m, ubuf_sz, h)
                               : svcSendSyncRequest(h);
    u32 ipc_rc = 0;
    Handle out_h = INVALID_HANDLE;
    if (R_SUCCEEDED(krc))
        extract_reply_info(m, req.is_tipc, &ipc_rc, &out_h);

    // 2. Transparent HEN SM proxy fallback on 0x1015 (sm::ResultNotAllowed)
    bool proxied = false;
    if (R_SUCCEEDED(krc) && ipc_rc == 0x1015u) {
        u8 fail_reply[0x100];
        memcpy(fail_reply, m, sizeof(fail_reply));
        Handle ph = INVALID_HANDLE;
        Result prc = MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
        if (g_hen_sm != INVALID_HANDLE) {
            const SmServiceName encoded = smEncodeName(svc_name);
            Service proxy = {};
            serviceCreate(&proxy, g_hen_sm);
            proxy.own_handle = 0;
            prc = serviceDispatchIn(&proxy, 1, encoded,
                .out_handle_attrs = {SfOutHandleAttr_HipcMove},
                .out_handles = &ph);
        }
        if (R_SUCCEEDED(prc) && ph != INVALID_HANDLE) {
            nupLogf("[svc-sm] GetService('%s') -> HEN proxy OK (h=0x%x, bypassed 0x1015)\n", svc_name, ph);
            if (req.is_tipc) write_tipc_reply(m, 0, ph);
            else write_cmif_reply(m, false, 0, NULL, 0, 0, ph, INVALID_HANDLE);
            out_h = ph;
            ipc_rc = 0;
            proxied = true;
        } else {
            // 3. Last-resort non-critical stand-in if BOTH real SM and HEN SM denied 0x1015
            if (!is_core_service(svc_name)) {
                VirtualObj st = { .kind = VOBJ_STANDIN };
                snprintf(st.standin_name, sizeof(st.standin_name), "%s", svc_name);
                const Handle sh = vhandle_alloc(&st);
                if (sh != INVALID_HANDLE) {
                    nupLogf("[svc-sm] GetService('%s') -> virtual stand-in h=0x%x (both SM & HEN denied)\n",
                            svc_name, sh);
                    if (req.is_tipc) write_tipc_reply(m, 0, sh);
                    else write_cmif_reply(m, false, 0, NULL, 0, 0, sh, INVALID_HANDLE);
                    regs[0] = 0;
                    return true;
                }
            }
            nupLogf("[svc-sm] GetService('%s') -> ACL_DENIED 0x1015 (HEN proxy rc=0x%x)\n", svc_name, prc);
            memcpy(m, fail_reply, sizeof(fail_reply));
        }
    }

    // 4. Tag tracked sysmodule sessions
    if (R_SUCCEEDED(krc) && R_SUCCEEDED(ipc_rc) && out_h != INVALID_HANDLE) {
        if (strcmp(svc_name, "fsp-srv") == 0)
            session_register(out_h, SESS_FSP_SRV);
        else if (strcmp(svc_name, "ldr:ro") == 0 || strcmp(svc_name, "ro:1") == 0)
            session_register(out_h, SESS_LDR_RO);
        else if (strcmp(svc_name, "aoc:u") == 0)
            session_register(out_h, SESS_AOC);
        else if (strncmp(svc_name, "bcat:", 5) == 0)
            session_register(out_h, SESS_BCAT);
        // Trace-only visibility: successes are silent on the normal path.
        // Proxied services already logged above; don't log twice.
        if (!proxied && nupTraceIsEnabled()) {
            u8 tls_save[0x100];
            memcpy(tls_save, armGetTls(), sizeof(tls_save));
            nupLogf("[svc-sm] GetService('%s') -> OK (h=0x%x)\n", svc_name, out_h);
            memcpy(armGetTls(), tls_save, sizeof(tls_save));
        }
    }

    regs[0] = krc;
    return true;
}

static bool handle_bcat_ipc(u64* regs, Handle h, u8* m, const u8* req_buf, bool is_domain,
                            bool with_user_buf, u64 ubuf_sz) {
    ParsedIpc req;
    if (!parse_ipc_request(req_buf, is_domain, &req))
        return false;
    if (req.type == 5u || req.type == 7u) {
        if (req.cmd == 0u) {
            const Result krc = with_user_buf ? svcSendSyncRequestWithUserBuffer(m, ubuf_sz, h)
                                             : svcSendSyncRequest(h);
            if (R_SUCCEEDED(krc)) {
                nupSpinLock(&g_svc_lock);
                TrackedSession* s2 = session_find_locked(h);
                if (s2) s2->is_domain = true;
                nupSpinUnlock(&g_svc_lock);
            }
            regs[0] = krc;
            return true;
        }
        return false;
    }
    const Result krc = with_user_buf ? svcSendSyncRequestWithUserBuffer(m, ubuf_sz, h)
                                     : svcSendSyncRequest(h);
    if (R_SUCCEEDED(krc)) {
        u32 res = 0; Handle dummy = INVALID_HANDLE;
        extract_reply_info(m, req.is_tipc, &res, &dummy);
        // Convert missing-donor-BCAT-storage errors (Module_Fs 2 or Module_Bcat 122) to clean offline FileNotFound
        if (R_FAILED(res) && (R_MODULE(res) == 2u || R_MODULE(res) == 122u)) {
            if (req.cmd == 10100u || req.cmd == 10101u || req.cmd == 10200u) {
                write_cmif_reply(m, req.is_domain, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            } else if (req.num_b > 0 || req.num_c > 0) {
                write_cmif_reply(m, req.is_domain, 0x147Au, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            }
        }
    }
    regs[0] = krc;
    return true;
}

static bool handle_ldr_ro_ipc(u64* regs, u8* m, const u8* req_buf) {
    const Handle ready = smGetServiceOverride(smEncodeName("ldr:ro"));
    if (ready == INVALID_HANDLE)
        return false;
    ParsedIpc req;
    if (!parse_ipc_request(req_buf, false, &req))
        return false;
    if (req.type == 5u || req.type == 7u) // Control
        return false;
    // Initialize (cmd 4) and NRR register/unregister (cmds 2, 3, 10): kaiHEN's pre-initialized
    // ldr:ro override accepts unsigned NROs directly without NRR or re-initialization.
    if (req.cmd == 2u || req.cmd == 3u || req.cmd == 4u || req.cmd == 10u) {
        write_cmif_reply(m, req.is_domain, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    // Dynamically patch any SVC instructions in NROs loaded by the game via nn::ro::LoadModule
    if (req.cmd == 0u && req.raw_in_bytes >= 24) {
        const u64 nro_src = rd64(req.raw_in + 8);
        const u64 nro_sz  = rd64(req.raw_in + 16);
        MemoryInfo mi = {};
        u32 pi = 0;
        if (nro_src >= 0x10000ull && nro_sz >= 0x80ull &&
            R_SUCCEEDED(svcQueryMemory(&mi, &pi, nro_src)) &&
            (mi.perm & (Perm_R | Perm_W)) == (Perm_R | Perm_W) &&
            nro_src + nro_sz <= mi.addr + mi.size) {
            if (elfPatchNroSvcs((u8*)(uintptr_t)nro_src, nro_sz, "ro_dynamic") > 0)
                armDCacheFlush((void*)(uintptr_t)nro_src, (size_t)nro_sz);
        }
        // Restore IPC request buffer before forwarding to ldr:ro (elfPatchNroSvcs may have logged)
        memcpy(m, req_buf, 0x100);
    }
    const Result rc = svcSendSyncRequest(ready);
    if (req.cmd == 0u && R_SUCCEEDED(rc)) {
        u8 reply_copy[0x100];
        memcpy(reply_copy, m, sizeof(reply_copy));
        u32 res = 0; Handle dummy = INVALID_HANDLE;
        extract_reply_info(reply_copy, false, &res, &dummy);
        if (R_SUCCEEDED(res)) {
            const u32 n = __atomic_add_fetch(&g_ro_loaded_cnt, 1, __ATOMIC_RELAXED);
            nupLogf("[svc-ro] LoadNro forwarded -> OK (dynamic=%u)\n", n);
        } else {
            nupLogf("[svc-ro] LoadNro forwarded -> FAILED 0x%x\n", res);
        }
        memcpy(m, reply_copy, sizeof(reply_copy));
    } else if (req.cmd == 1u && R_SUCCEEDED(rc)) {
        if (g_ro_loaded_cnt > 0) __atomic_sub_fetch(&g_ro_loaded_cnt, 1, __ATOMIC_RELAXED);
    }
    regs[0] = rc;
    return true;
}

static bool handle_aoc_ipc(u64* regs, Handle h, u8* m, const u8* req_buf, bool is_domain,
                           bool with_user_buf, u64 ubuf_sz) {
    ParsedIpc req;
    if (!parse_ipc_request(req_buf, is_domain, &req))
        return false;
    if (req.type == 5u || req.type == 7u) {
        if (req.cmd == 0u) {
            const Result krc = with_user_buf ? svcSendSyncRequestWithUserBuffer(m, ubuf_sz, h)
                                             : svcSendSyncRequest(h);
            if (R_SUCCEEDED(krc)) {
                nupSpinLock(&g_svc_lock);
                TrackedSession* s2 = session_find_locked(h);
                if (s2) s2->is_domain = true;
                nupSpinUnlock(&g_svc_lock);
            }
            regs[0] = krc;
            return true;
        }
        return false;
    }
    if (req.is_domain && req.domain_cmd == 2u)
        return false;

    const bool dom = req.is_domain;
    switch (req.cmd) {
    case 2: { // CountAddOnContent
        const u32 cnt = (u32)g_dlc_count;
        write_cmif_reply(m, dom, 0, &cnt, sizeof(cnt), 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    case 3: { // ListAddOnContent(u32 offset, u32 count) -> out u32 written + B/C buf u32[]
        const u32 off = rd32(req.raw_in + 0);
        const u32 want = rd32(req.raw_in + 4);
        IpcBuf out_b = req.num_b ? req.b_bufs[0] : (req.num_c ? req.c_bufs[0] : (IpcBuf){0, 0});
        u32 n = 0;
        if (out_b.addr && out_b.size >= 4) {
            u32* dst = (u32*)(uintptr_t)out_b.addr;
            const u32 max_n = (u32)(out_b.size / 4u);
            for (u32 k = off; k < (u32)g_dlc_count && n < want && n < max_n; k++)
                dst[n++] = (u32)g_dlcs[k].index;
        }
        write_cmif_reply(m, dom, 0, &n, sizeof(n), 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    case 5: { // GetAddOnContentBaseId
        const u64 base_id = (g_title_id & ~0xFFFull) + 0x1000ull;
        write_cmif_reply(m, dom, 0, &base_id, sizeof(base_id), 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    case 6:  // PrepareAddOnContentByApplicationId
    case 7:  // PrepareAddOnContent
    case 11: // NotifyMountAddOnContent
    case 12: // NotifyUnmountAddOnContent
    case 50: // CheckAddOnContentMountStatus
        write_cmif_reply(m, dom, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    case 8: { // GetAddOnContentListChangedEvent -> dummy virtual event handle
        VirtualObj ev = { .kind = VOBJ_EVENT };
        const Handle eh = vhandle_alloc(&ev);
        write_cmif_reply(m, dom, eh != INVALID_HANDLE ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                         NULL, 0, 0, INVALID_HANDLE, eh);
        regs[0] = 0;
        return true;
    }
    default:
        return false;
    }
}

static void format_save_dir(u64 app_id, u8 save_type, u16 index, u64 sys_id, char* out, size_t out_sz) {
    const u64 tid = app_id ? app_id : g_title_id;
    switch (save_type) {
    case 0: // System
        snprintf(out, out_sz, "/kaihen/saves/%016llx/sys_%016llx",
                 (unsigned long long)tid, (unsigned long long)sys_id);
        break;
    case 2: // BCAT
    case 6: // SystemBcat
        snprintf(out, out_sz, "/kaihen/saves/%016llx/bcat", (unsigned long long)tid);
        break;
    case 3: // Device
        snprintf(out, out_sz, "/kaihen/saves/%016llx/device", (unsigned long long)tid);
        break;
    case 4: // Temporary
        snprintf(out, out_sz, "/kaihen/saves/%016llx/temp", (unsigned long long)tid);
        break;
    case 5: // Cache
        snprintf(out, out_sz, "/kaihen/saves/%016llx/cache_%u", (unsigned long long)tid, (unsigned)index);
        break;
    default: // Account (1)
        snprintf(out, out_sz, "/kaihen/saves/%016llx/user", (unsigned long long)tid);
        break;
    }
}

static bool handle_fsp_srv_ipc(u64* regs, Handle h, TrackedSession* sess, u8* m, const u8* req_buf,
                               bool with_user_buf, u64 ubuf_sz) {
    ParsedIpc req;
    if (!parse_ipc_request(req_buf, sess->is_domain, &req))
        return false;

    // Control cmd 0: ConvertCurrentObjectToDomain
    if (req.type == 5u || req.type == 7u) {
        if (req.cmd == 0u) {
            const Result krc = with_user_buf ? svcSendSyncRequestWithUserBuffer(m, ubuf_sz, h)
                                             : svcSendSyncRequest(h);
            if (R_SUCCEEDED(krc)) {
                nupSpinLock(&g_svc_lock);
                TrackedSession* s2 = session_find_locked(h);
                if (s2) s2->is_domain = true;
                nupSpinUnlock(&g_svc_lock);
            }
            regs[0] = krc;
            return true;
        }
        return false;
    }

    // Domain dispatch to virtual object
    if (req.is_domain && is_vobj(req.domain_obj)) {
        if (req.domain_cmd == 2u) { // CloseVirtualHandle
            vobj_free(req.domain_obj);
            write_cmif_reply(m, true, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            regs[0] = 0;
            return true;
        }
        VirtualObj* vo = &g_vobjs[req.domain_obj - VOBJ_BASE];
        if (vo->kind != VOBJ_NONE && handle_vobj_ipc(vo, m, &req)) {
            regs[0] = 0;
            return true;
        }
        write_cmif_reply(m, true, FS_RC_INVALID_ARG, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }

    if (req.is_domain && req.domain_cmd != 1u)
        return false;

    const bool dom = req.is_domain;

    // --- Hard NAND write / BIS guards ---
    if (req.cmd == 11u || req.cmd == 12u || req.cmd == 19u || req.cmd == 21u) {
        nupLogf("[svc-fs] BLOCKED NAND/BIS fsp-srv cmd %u\n", req.cmd);
        write_cmif_reply(m, dom, FS_RC_NAND_BLOCKED, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }

    // --- RomFS / DLC IStorage commands ---
    if (req.cmd == 200u || req.cmd == 201u || req.cmd == 202u || req.cmd == 205u) {
        VfsRomfs* r = NULL;
        if (req.cmd == 200u) { // OpenDataStorageByCurrentProcess
            r = get_active_romfs();
            nupLogf("[svc-fs] cmd 200 (OpenDataStorageByCurrentProcess) -> %s\n", r ? "SD RomFS" : "MISS");
        } else if (req.cmd == 205u) { // OpenDataStorageWithProgramIndex(u8 prog_idx)
            const u32 pidx = req.raw_in[0];
            r = get_program_romfs(pidx);
            nupLogf("[svc-fs] cmd 205 (OpenDataStorageWithProgramIndex prog=%u) -> %s\n", pidx, r ? "SD RomFS" : "MISS");
        } else if (req.cmd == 201u) { // OpenDataStorageByProgramId(u64 pid)
            const u64 pid = rd64(req.raw_in + 0);
            if (pid == g_title_id || (g_title_id && (pid & ~0xFFFull) == (g_title_id & ~0xFFFull))) {
                r = get_program_romfs((u32)(pid & 0xFu));
                nupLogf("[svc-fs] cmd 201 (OpenDataStorageByProgramId %016llx) -> %s\n",
                        (unsigned long long)pid, r ? "SD RomFS" : "MISS");
            } else {
                return false; // System data (e.g. shared fonts / firmware archives): pass through
            }
        } else if (req.cmd == 202u) { // OpenDataStorageByDataId(u8 storage_id, u64 data_id)
            const u64 data_id = rd64(req.raw_in + 8);
            if ((data_id >> 12) == 0x0100000000000ull || (data_id >> 12) == 0x0400000000000ull)
                return false; // System data archive (fonts, timezones, etc.): pass through
            const int dlc_idx = (int)(data_id & 0xFFFull);
            r = get_dlc_romfs(dlc_idx);
            nupLogf("[svc-fs] cmd 202 (OpenDataStorageByDataId %016llx dlc=%d) -> %s\n",
                    (unsigned long long)data_id, dlc_idx, r ? "SD DLC RomFS" : "NOT FOUND");
            if (!r) {
                write_cmif_reply(m, dom, FS_RC_TARGET_NOT_FOUND, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                regs[0] = 0;
                return true;
            }
        }

        if (!r) {
            write_cmif_reply(m, dom, FS_RC_TARGET_NOT_FOUND, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            regs[0] = 0;
            return true;
        }
        VirtualObj vo = { .kind = VOBJ_STORAGE, .read_only = true, .romfs = r };
        if (dom) {
            const u32 oid = vobj_alloc(&vo);
            write_cmif_reply(m, true, oid ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                             NULL, 0, oid, INVALID_HANDLE, INVALID_HANDLE);
        } else {
            const Handle vh = vhandle_alloc(&vo);
            write_cmif_reply(m, false, vh != INVALID_HANDLE ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                             NULL, 0, 0, vh, INVALID_HANDLE);
        }
        regs[0] = 0;
        return true;
    }

    // --- SaveData / DeviceSave / Cache / Temp / BCAT -> SD (ZERO NAND WRITES) ---
    if (req.cmd == 51u || req.cmd == 52u || req.cmd == 53u) {
        // raw_in: u8 space_id (padded to 8 bytes) + FsSaveDataAttribute (0x40 bytes at +8)
        u64 app_id = 0, sys_id = 0;
        u8 save_type = 1;
        u16 save_idx = 0;
        if (req.raw_in_bytes >= 8 + 0x24) {
            app_id = rd64(req.raw_in + 8 + 0x00);
            sys_id = rd64(req.raw_in + 8 + 0x18);
            save_type = req.raw_in[8 + 0x20];
            memcpy(&save_idx, req.raw_in + 8 + 0x22, 2);
        }
        const bool is_ro = (req.cmd == 53u);
        const bool is_other = (app_id != 0 && g_title_id != 0 &&
                               (app_id & ~0xFFFull) != (g_title_id & ~0xFFFull));
        char save_root[0x300];
        format_save_dir(app_id, save_type, save_idx, sys_id, save_root, sizeof(save_root));

        if (is_other) {
            if (!is_ro || !sd_dir_exists(save_root)) {
                nupLogf("[svc-fs] cmd %u other-title save %016llx (type=%u) -> 0x7D402\n",
                        req.cmd, (unsigned long long)app_id, (unsigned)save_type);
                write_cmif_reply(m, dom, FS_RC_TARGET_NOT_FOUND, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
                regs[0] = 0;
                return true;
            }
        } else if (!is_ro) {
            ensure_sd_dir_recursive(save_root);
        } else if (!sd_dir_exists(save_root)) {
            write_cmif_reply(m, dom, FS_RC_TARGET_NOT_FOUND, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            regs[0] = 0;
            return true;
        }

        VirtualObj vo = {};
        vo.kind = VOBJ_FS;
        vo.read_only = is_ro;
        snprintf(vo.sd_root, sizeof(vo.sd_root), "%s", save_root);
        nupLogf("[svc-fs] cmd %u save(type=%u idx=%u ro=%d) -> SD '%s'\n",
                req.cmd, (unsigned)save_type, (unsigned)save_idx, is_ro ? 1 : 0, save_root);
        if (dom) {
            const u32 oid = vobj_alloc(&vo);
            write_cmif_reply(m, true, oid ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                             NULL, 0, oid, INVALID_HANDLE, INVALID_HANDLE);
        } else {
            const Handle vh = vhandle_alloc(&vo);
            write_cmif_reply(m, false, vh != INVALID_HANDLE ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                             NULL, 0, 0, vh, INVALID_HANDLE);
        }
        regs[0] = 0;
        return true;
    }

    // SaveDataInfoReader (cmds 57, 60, 61) -> virtual SD save enumerator
    if (req.cmd == 57u || req.cmd == 60u || req.cmd == 61u) {
        VirtualObj vo = { .kind = VOBJ_SAVE_READER, .reader_pos = 0 };
        if (dom) {
            const u32 oid = vobj_alloc(&vo);
            write_cmif_reply(m, true, oid ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                             NULL, 0, oid, INVALID_HANDLE, INVALID_HANDLE);
        } else {
            const Handle vh = vhandle_alloc(&vo);
            write_cmif_reply(m, false, vh != INVALID_HANDLE ? 0 : MAKERESULT(Module_Libnx, LibnxError_OutOfMemory),
                             NULL, 0, 0, vh, INVALID_HANDLE);
        }
        regs[0] = 0;
        return true;
    }

    // SaveDataExtraData read/write (cmds 27, 35, 36) & SaveDataMetaFile (cmd 58) -> never touch NAND
    if (req.cmd == 27u || req.cmd == 35u) {
        if (req.num_b > 0 && req.b_bufs[0].addr && req.b_bufs[0].size >= sizeof(FsSaveDataExtraData)) {
            FsSaveDataExtraData* ex = (FsSaveDataExtraData*)(uintptr_t)req.b_bufs[0].addr;
            memset(ex, 0, sizeof(*ex));
            ex->attr.application_id = g_title_id;
            ex->attr.save_data_type = 1;
            ex->owner_id = g_title_id;
            ex->data_size = 0x4000000ll;
            ex->journal_size = 0x4000000ll;
        }
        write_cmif_reply(m, dom, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    if (req.cmd == 36u) {
        write_cmif_reply(m, dom, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    if (req.cmd == 58u) {
        write_cmif_reply(m, dom, FS_RC_TARGET_NOT_FOUND, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }

    // Save / Cache management commands -> SD-backed no-ops (never touch NAND)
    if (req.cmd == 22u || req.cmd == 23u || req.cmd == 24u || req.cmd == 25u ||
        req.cmd == 28u || req.cmd == 67u || req.cmd == 68u) {
        nupLogf("[svc-fs] cmd %u save/cache mgmt -> virtualized OK (no NAND write)\n", req.cmd);
        write_cmif_reply(m, dom, 0, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    if (req.cmd == 34u || req.cmd == 69u) { // GetCacheStorageSize
        const s64 sizes[2] = { 0x80000000ll, 0x80000000ll };
        write_cmif_reply(m, dom, 0, sizes, sizeof(sizes), 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }
    if (req.cmd == 70u) { // GetCacheStorageMax
        const struct { s32 max_idx; s32 pad; s64 max_sz; } out = { 16, 0, 0x80000000ll };
        write_cmif_reply(m, dom, 0, &out, sizeof(out), 0, INVALID_HANDLE, INVALID_HANDLE);
        regs[0] = 0;
        return true;
    }

    return false;
}

// --- Public lifecycle API ---

void nupSvcHipcInit(NupArchive* nup, FsFileSystem* sd,
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
    g_host_heap_base = 0;
    g_host_heap_keep = 0;
    g_in_startup = 0;
    g_vam_1m_calls = 0;
    g_vam_probe_capped = 0;
    g_ro_loaded_cnt = 0;
    nupSpinInit(&g_svc_lock);

    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_vobjs, 0, sizeof(g_vobjs));
    memset(g_vhandles, 0, sizeof(g_vhandles));
    g_has_rom_overlay = false;
    g_rom_overlay_root[0] = '\0';
    g_active_romfs_built = false;
    memset(&g_active_romfs, 0, sizeof(g_active_romfs));
    memset(g_prog_romfs, 0, sizeof(g_prog_romfs));
    memset(g_prog_romfs_built, 0, sizeof(g_prog_romfs_built));
    memset(g_dlcs, 0, sizeof(g_dlcs));
    g_dlc_count = 0;

    if (g_nup && g_nup->raw_root[0]) {
        const char* app_root = g_nup->raw_app_root[0] ? g_nup->raw_app_root : g_nup->raw_root;
        char ov[0x300];
        if (g_nup->raw_is_subprogram) {
            format_sd_subpath(g_nup->raw_root, "romfs_update", ov, sizeof(ov));
        } else {
            format_sd_subpath(app_root, "romfs_update", ov, sizeof(ov));
            if (!sd_dir_exists(ov))
                format_sd_subpath(g_nup->raw_root, "romfs_update", ov, sizeof(ov));
        }
        if (sd_dir_exists(ov)) {
            g_has_rom_overlay = true;
            snprintf(g_rom_overlay_root, sizeof(g_rom_overlay_root), "%s", ov);
            nupLogf("[svc-fs] romfs_update overlay active: %s\n", g_rom_overlay_root);
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
    }

    if (g_title_id) {
        char dlc_global[0x300];
        snprintf(dlc_global, sizeof(dlc_global), "/kaihen/dlc/%016llx", (unsigned long long)g_title_id);
        scan_dlc_parent(dlc_global);
    }

    sort_dlcs();
    if (g_dlc_count > 0) {
        nupLogf("[svc-aoc] discovered %d SD DLC(s) for tid=%016llx\n",
                g_dlc_count, (unsigned long long)g_title_id);
        for (int i = 0; i < g_dlc_count && i < 8; i++)
            nupLogf("  dlc[%d] -> SD %s\n", g_dlcs[i].index, g_dlcs[i].sd_root);
    }

    // Pre-build virtual RomFS metadata tables BEFORE shrink_libnx_heap_for_game()
    // so runtime IStorage::Read performs zero heap allocations.
    get_active_romfs();
    if (g_nup && g_nup->raw_root[0]) {
        const char* app_root = g_nup->raw_app_root[0] ? g_nup->raw_app_root : g_nup->raw_root;
        char game_dir[0x300];
        format_sd_subpath(app_root, "game", game_dir, sizeof(game_dir));
        const char* base = sd_dir_exists(game_dir) ? game_dir : app_root;
        for (u32 p = 0; p < MAX_PROG_ROMS; p++) {
            char probe[0x300];
            if (p == 0) {
                format_sd_subpath(base, "romfs", probe, sizeof(probe));
            } else {
                char sub[32];
                snprintf(sub, sizeof(sub), "program%u/romfs", p);
                format_sd_subpath(base, sub, probe, sizeof(probe));
            }
            if (g_nup->raw_romfs_root[0] && strcmp(probe, g_nup->raw_romfs_root) == 0)
                continue;
            if (sd_dir_exists(probe))
                get_program_romfs(p);
        }
    }
    for (int i = 0; i < g_dlc_count; i++)
        get_dlc_romfs(g_dlcs[i].index);
}

static void note_romfs_heap(const VfsRomfs* r, u64* high) {
    if (!r || !r->ready) return;
    if (r->meta_buf) {
        const u64 e = (u64)(uintptr_t)r->meta_buf + r->file_data_off;
        if (e > *high) *high = e;
    }
    if (r->spans) {
        const u64 e = (u64)(uintptr_t)r->spans + (u64)r->span_cap * sizeof(VfsRomfsSpan);
        if (e > *high) *high = e;
    }
    if (r->path_pool) {
        const u64 e = (u64)(uintptr_t)r->path_pool + (u64)r->path_cap;
        if (e > *high) *high = e;
    }
}

u64 nupSvcHipcMaxHeapAddr(void) {
    u64 high = 0;
    note_romfs_heap(&g_active_romfs, &high);
    for (u32 p = 0; p < MAX_PROG_ROMS; p++)
        note_romfs_heap(&g_prog_romfs[p], &high);
    for (int i = 0; i < g_dlc_count; i++)
        note_romfs_heap(&g_dlcs[i].romfs, &high);
    return high;
}

void nupSvcHipcSetVfsPlugin(Handle vfs_session, u32 vfs_flags) {
    nupSpinInit(&g_vfs_ipc_lock);
    if (vfs_session != INVALID_HANDLE) {
        serviceCreate(&g_vfs_plugin, vfs_session);
        g_vfs_plugin.own_handle = 0;
        g_vfs_plugin_ok = true;
        g_vfs_flags = vfs_flags;
    } else {
        memset(&g_vfs_plugin, 0, sizeof(g_vfs_plugin));
        g_vfs_plugin_ok = false;
        g_vfs_flags = NUPVFS_FLAG_MODS | NUPVFS_FLAG_CACHE;
    }
}

void nupSvcHipcSetNvHandle(Handle nv_session) {
    g_preopened_nv = nv_session;
}

void nupSvcHipcSetHostHeap(u64 heap_base, u64 host_keep) {
    g_host_heap_base = heap_base;
    g_host_heap_keep = host_keep;
    g_game_heap_size = 0;
    g_compat_heap_reserved = 0;
    g_compat_heap_marked = false;
    nupLogf("[svc-mem] host heap slice locked: base=0x%llx keep=0x%llx\n",
            (unsigned long long)heap_base, (unsigned long long)host_keep);
}

void nupSvcHipcMarkCompatHeapEnd(void) {
    if (g_compat_heap_marked)
        return;
    g_compat_heap_marked = true;
    g_compat_heap_reserved = g_game_heap_size;
    if (g_compat_heap_reserved > 0) {
        nupLogf("[svc-mem] marked compat heap reservation: 0x%llx\n",
                (unsigned long long)g_compat_heap_reserved);
    }
}

void nupSvcHipcSetInStartup(bool in_startup) {
    __atomic_store_n(&g_in_startup, in_startup ? 1 : 0, __ATOMIC_RELEASE);
    if (in_startup) {
        __atomic_store_n(&g_vam_1m_calls, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&g_vam_probe_capped, 0, __ATOMIC_RELAXED);
    }
}

// --- Central SVC Dispatcher (called from svc_entry.s on private 64 KiB stack) ---

static volatile u32 g_svc_trace_cnt = 0;
static volatile u64 g_svc_counts[0x40] = {0};

int nupSvcDispatch(u64* regs, u32 svc_num) {
    if (nupTraceIsEnabled()) {
        const u32 n = __atomic_fetch_add(&g_svc_trace_cnt, 1, __ATOMIC_RELAXED);
        if (svc_num < 0x40u)
            __atomic_fetch_add(&g_svc_counts[svc_num], 1ULL, __ATOMIC_RELAXED);
        if (n < 32u) {
            u8 tls_save[0x100];
            memcpy(tls_save, armGetTls(), sizeof(tls_save));
            nupLogf("[svc-trace #%u] svc=0x%02x x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx\n",
                    n, svc_num,
                    (unsigned long long)regs[0], (unsigned long long)regs[1],
                    (unsigned long long)regs[2], (unsigned long long)regs[3]);
            memcpy(armGetTls(), tls_save, sizeof(tls_save));
        } else if ((n & 0xFFFu) == 0u) {
            // Periodic summary so nnMain-phase SVCs stay visible without per-call spam.
            u8 tls_save[0x100];
            memcpy(tls_save, armGetTls(), sizeof(tls_save));
            nupLogf("[svc-trace #%u] summary 0x1F=%llu 0x21/0x22=%llu/%llu 0x29=%llu\n", n,
                    (unsigned long long)__atomic_load_n(&g_svc_counts[0x1Fu], __ATOMIC_RELAXED),
                    (unsigned long long)__atomic_load_n(&g_svc_counts[0x21u], __ATOMIC_RELAXED),
                    (unsigned long long)__atomic_load_n(&g_svc_counts[0x22u], __ATOMIC_RELAXED),
                    (unsigned long long)__atomic_load_n(&g_svc_counts[0x29u], __ATOMIC_RELAXED));
            memcpy(armGetTls(), tls_save, sizeof(tls_save));
        }
    }
    switch (svc_num) {
    case 0x01: { // svcSetHeapSize(out_addr: x1, size: x1_in -> x0=rc, x1=addr)
        if (!g_host_heap_keep)
            return 0;
        const u64 req_sz = regs[1];
        void* base = NULL;
        const Result rc = svcSetHeapSize(&base, (size_t)(g_host_heap_keep + req_sz));
        if (R_SUCCEEDED(rc))
            g_game_heap_size = req_sz;
        regs[0] = rc;
        regs[1] = R_SUCCEEDED(rc) ? ((u64)(uintptr_t)base + g_host_heap_keep) : 0;
        nupLogf("[svc-mem] SetHeapSize(0x%llx) -> 0x%x addr=0x%llx (total=0x%llx)\n",
                (unsigned long long)req_sz, rc, (unsigned long long)regs[1],
                (unsigned long long)(g_host_heap_keep + req_sz));
        return 1;
    }

    case 0x16: { // svcCloseHandle(handle: w0)
        const Handle h = (Handle)regs[0];
        if (is_vhandle(h)) {
            vhandle_free(h);
            regs[0] = 0;
            return 1;
        }
        session_forget(h);
        return 0;
    }

    case 0x18: { // svcWaitSynchronization(out_idx: w1, handles: x1, num: w2, timeout: x3)
        const Handle* in_h = (const Handle*)(uintptr_t)regs[1];
        const s32 cnt = (s32)regs[2];
        if (!in_h || cnt <= 0 || cnt > 64)
            return 0;
        bool has_virt = false;
        for (s32 i = 0; i < cnt; i++) {
            if (is_vhandle(in_h[i])) { has_virt = true; break; }
        }
        if (!has_virt)
            return 0;
        Handle real_h[64];
        s32 map_idx[64];
        s32 rcnt = 0;
        for (s32 i = 0; i < cnt; i++) {
            if (!is_vhandle(in_h[i])) {
                real_h[rcnt] = in_h[i];
                map_idx[rcnt] = i;
                rcnt++;
            }
        }
        s32 out_i = -1;
        if (rcnt == 0) {
            // All handles virtual (never signaled): report timeout, never call kernel with 0 handles.
            regs[0] = 0xEA01u;
            regs[1] = (u64)(s64)-1;
            return 1;
        }
        const Result rc = svcWaitSynchronization(&out_i, real_h, rcnt, (u64)regs[3]);
        regs[0] = rc;
        regs[1] = (R_SUCCEEDED(rc) && out_i >= 0 && out_i < rcnt) ? (u64)(s64)map_idx[out_i] : (u64)(s64)out_i;
        return 1;
    }

    case 0x1F: { // svcConnectToNamedPort(out_handle: w1, name: x1_in)
        const char* name = (const char*)(uintptr_t)regs[1];
        Handle out_h = INVALID_HANDLE;
        const Result rc = svcConnectToNamedPort(&out_h, name);
        regs[0] = rc;
        regs[1] = out_h;
        if (R_SUCCEEDED(rc) && name && strcmp(name, "sm:") == 0)
            session_register(out_h, SESS_SM);
        return 1;
    }

    case 0x21:   // svcSendSyncRequest(handle: w0)
    case 0x22: { // svcSendSyncRequestWithUserBuffer(buf: x0, size: x1, handle: w2)
        const bool with_ubuf = (svc_num == 0x22);
        const Handle h = with_ubuf ? (Handle)regs[2] : (Handle)regs[0];
        u8* m = with_ubuf ? (u8*)(uintptr_t)regs[0] : (u8*)armGetTls();
        const u64 ubuf_sz = with_ubuf ? regs[1] : 0x100ull;

        // Snapshot incoming IPC buffer onto private 64 KiB stack so logging / SD IPC
        // (which use armGetTls()) can never clobber the parsed request.
        u8 req_buf[0x100];
        memcpy(req_buf, m, sizeof(req_buf));

        // 1. Standalone virtual handle (non-domain VOBJ_* or VOBJ_STANDIN)
        if (is_vhandle(h)) {
            VirtualObj* vo = &g_vhandles[h - VHANDLE_BASE];
            ParsedIpc req;
            if (vo->kind != VOBJ_NONE && parse_ipc_request(req_buf, vo->is_domain, &req)) {
                if (req.type == 2u || req.type == 15u) { // Close
                    regs[0] = 0xF601u;
                    return 1;
                }
                if (handle_vobj_ipc(vo, m, &req)) {
                    regs[0] = 0;
                    return 1;
                }
            }
            write_cmif_reply(m, false, FS_RC_INVALID_ARG, NULL, 0, 0, INVALID_HANDLE, INVALID_HANDLE);
            regs[0] = 0;
            return 1;
        }

        // 2. Tracked real sysmodule session
        nupSpinLock(&g_svc_lock);
        TrackedSession* s = session_find_locked(h);
        TrackedSession snap = s ? *s : (TrackedSession){0};
        nupSpinUnlock(&g_svc_lock);

        if (snap.kind == SESS_NONE)
            return 0;

        bool handled = false;
        if (snap.kind == SESS_SM)
            handled = handle_sm_ipc(regs, h, m, req_buf, with_ubuf, ubuf_sz);
        else if (snap.kind == SESS_LDR_RO)
            handled = handle_ldr_ro_ipc(regs, m, req_buf);
        else if (snap.kind == SESS_AOC)
            handled = handle_aoc_ipc(regs, h, m, req_buf, snap.is_domain, with_ubuf, ubuf_sz);
        else if (snap.kind == SESS_FSP_SRV)
            handled = handle_fsp_srv_ipc(regs, h, &snap, m, req_buf, with_ubuf, ubuf_sz);
        else if (snap.kind == SESS_BCAT)
            handled = handle_bcat_ipc(regs, h, m, req_buf, snap.is_domain, with_ubuf, ubuf_sz);

        if (!handled) {
            // Restore original request bytes in case a handler logged before declining
            memcpy(m, req_buf, sizeof(req_buf));
            return 0;
        }
        return 1;
    }

    case 0x29: { // svcGetInfo(out: x1, type: w1_in, handle: w2_in, sub: x3_in)
        const u32 type = (u32)regs[1];
        const Handle h = (Handle)regs[2];
        const u64 sub = regs[3];
        if (h != CUR_PROCESS_HANDLE || !g_host_heap_keep)
            return 0;
        if (type == InfoType_HeapRegionAddress) {
            u64 val = 0;
            const Result rc = svcGetInfo(&val, type, h, sub);
            if (R_SUCCEEDED(rc))
                val += g_host_heap_keep;
            regs[0] = rc;
            regs[1] = val;
            return 1;
        }
        if (type == InfoType_HeapRegionSize) {
            u64 val = 0;
            const Result rc = svcGetInfo(&val, type, h, sub);
            if (R_SUCCEEDED(rc))
                val = (val > g_host_heap_keep) ? (val - g_host_heap_keep) : 0;
            regs[0] = rc;
            regs[1] = val;
            return 1;
        }
        if (type == InfoType_TotalMemorySize || type == InfoType_TotalNonSystemMemorySize) {
            u64 val = 0;
            const Result rc = svcGetInfo(&val, type, h, sub);
            if (R_SUCCEEDED(rc)) {
                val = (val > g_host_heap_keep) ? (val - g_host_heap_keep) : 0;
                if (g_caps.target_is_switch1 && val > 0xD0000000ull)
                    val = 0xD0000000ull; // 3.25 GiB Switch 1 ceiling
            }
            regs[0] = rc;
            regs[1] = val;
            return 1;
        }
        if (type == InfoType_UsedMemorySize || type == InfoType_UsedNonSystemMemorySize) {
            u64 val = 0;
            const Result rc = svcGetInfo(&val, type, h, sub);
            if (R_SUCCEEDED(rc)) {
                const u64 hide = g_host_heap_keep + (g_caps.target_is_switch1 ? g_compat_heap_reserved : 0ull);
                val = (val > hide) ? (val - hide) : 0;
            }
            regs[0] = rc;
            regs[1] = val;
            return 1;
        }
        return 0;
    }

    case 0x2C: { // svcMapPhysicalMemory(addr: x0, size: x1)
        const u64 size = regs[1];
        if (size == 0x100000ull && __atomic_load_n(&g_in_startup, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&g_vam_probe_capped, __ATOMIC_RELAXED)) {
            const u32 calls = __atomic_fetch_add(&g_vam_1m_calls, 1, __ATOMIC_RELAXED);
            const bool sw1_cap = g_caps.target_is_switch1 && calls >= 3072u;
            bool sysres_cap = false;
            u64 sys_tot = 0, sys_used = 0;
            if (sw1_cap || (calls >= 512u && (calls & 63u) == 0)) {
                svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
                svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
                if (!sw1_cap && sys_tot > 0) {
                    const u64 reserve = (sys_tot >= 0x2000000ull) ? 0x1000000ull : (sys_tot * 3ull) / 8ull;
                    if (sys_used + reserve >= sys_tot)
                        sysres_cap = true;
                }
            }
            if (sw1_cap || sysres_cap) {
                __atomic_store_n(&g_vam_probe_capped, 1, __ATOMIC_RELEASE);
                nupLogf("[svc-mem] MapPhysicalMemory(0x%llx, 1MiB) -> CAPPED ONCE 0x1203 (%s calls=%u sysres=0x%llx/0x%llx)\n",
                        (unsigned long long)regs[0], sw1_cap ? "sw1-3g" : "sysres-reserve",
                        calls, (unsigned long long)sys_used, (unsigned long long)sys_tot);
                regs[0] = 0x1203u;
                return 1;
            }
        }
        return 0;
    }

    default:
        return 0;
    }
}
