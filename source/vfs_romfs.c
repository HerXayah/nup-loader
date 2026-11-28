// SPDX-License-Identifier: MIT
#include "vfs_romfs.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROMFS_ENTRY_EMPTY 0xFFFFFFFFu
#define ROMFS_HEADER_SIZE 0x50u
#define ROMFS_DIR_HDR_SZ  0x18u
#define ROMFS_FILE_HDR_SZ 0x20u

#ifdef NUPVFS_PLUGIN
// Resident plugin has an 8 MiB private heap: bail quickly on huge RomFS trees
// (e.g. 250k-file games) so nup-loader falls back to its local VFS immediately.
#define VFS_DIR_BATCH      64u
#define VFS_MAX_DIRS       4096u
#define VFS_MAX_FILES      16384u
#define VFS_MAX_PATH_POOL  (2u * 1024u * 1024u)
#else
#define VFS_DIR_BATCH      128u
#endif

static VfsRomfsProgressFn g_progress_cb = NULL;

void vfsRomfsSetProgressCallback(VfsRomfsProgressFn fn) {
    g_progress_cb = fn;
}

typedef struct {
    u64 header_size;
    u64 dir_hash_off;
    u64 dir_hash_size;
    u64 dir_table_off;
    u64 dir_table_size;
    u64 file_hash_off;
    u64 file_hash_size;
    u64 file_table_off;
    u64 file_table_size;
    u64 file_data_off;
} RomfsBinHeader;

_Static_assert(sizeof(RomfsBinHeader) == ROMFS_HEADER_SIZE, "RomfsBinHeader size");

typedef struct {
    u32 parent_idx;
    u32 first_child_dir;
    u32 next_sibling;
    u32 first_file;
    u32 name_off;
    u32 name_len;
    u32 table_off;
    u32 hash_next;
} BuildDir;

typedef struct {
    u32 parent_idx;
    u32 next_sibling;
    u32 name_off;
    u32 name_len;
    u32 sd_path_off;
    u32 table_off;
    u32 hash_next;
    u32 deleted;
    u64 data_off;
    u64 size;
} BuildFile;

typedef struct {
    u32 dir_idx;
    u32 dir_path_off;
    u32 depth;
} WalkWorkItem;

typedef struct {
    FsFileSystem* sd;
    BuildDir* dirs;
    u32 dir_count;
    u32 dir_cap;
    BuildFile* files;
    u32 file_count;
    u32 file_cap;
    char* name_pool;
    u32 name_used;
    u32 name_cap;
    char* path_pool;
    u32 path_used;
    u32 path_cap;
    char* dir_path_pool;
    u32 dir_path_used;
    u32 dir_path_cap;
    FsDirectoryEntry* ents;
    u32 dirs_visited;
    u32 layer_added;
    u32 layer_replaced;
    u32 layer_deleted;
    bool failed;
} RomfsBuilder;

static u32 align4_u32(u32 v) { return (v + 3u) & ~3u; }
static u64 align16_u64(u64 v) { return (v + 15ull) & ~15ull; }

static u32 next_growth_cap(u32 cap, u32 min_init, u32 need) {
    u32 ncap = (cap == 0) ? min_init : ((cap >= (4u << 20)) ? (cap + (cap >> 1)) : (cap * 2u));
    while (ncap < need) {
        u32 next = (ncap >= (4u << 20)) ? (ncap + (ncap >> 1)) : (ncap * 2u);
        if (next <= ncap) { ncap = need; break; }
        ncap = next;
    }
    return ncap;
}

static u32 romfs_hash_bucket_count(u32 entries) {
    if (entries < 3) return 3;
    if (entries < 19) return entries | 1u;
    u32 c = entries;
    while ((c % 2u) == 0 || (c % 3u) == 0 || (c % 5u) == 0 ||
           (c % 7u) == 0 || (c % 11u) == 0 || (c % 13u) == 0) {
        c++;
    }
    return c;
}

static u32 romfs_calc_hash(u32 parent_off, const char* name, u32 name_len) {
    u32 h = parent_off ^ 123456789u;
    for (u32 i = 0; i < name_len; i++) {
        h = (h >> 5) | (h << 27);
        h ^= (u8)name[i];
    }
    return h;
}

static u32 pool_append(char** pool, u32* used, u32* cap, const char* s, u32 len, u32 max_bytes, bool* failed) {
    const u32 need = *used + len + 1;
    if (max_bytes && need > max_bytes) {
        *failed = true;
        return 0;
    }
    if (need > *cap) {
        u32 ncap = next_growth_cap(*cap, 4096u, need);
        if (max_bytes && ncap > max_bytes) ncap = max_bytes;
        char* nb = (char*)realloc(*pool, ncap);
        if (!nb) { *failed = true; return 0; }
        *pool = nb;
        *cap = ncap;
    }
    const u32 off = *used;
    if (len) memcpy(*pool + off, s, len);
    (*pool)[off + len] = '\0';
    *used = need;
    return off;
}

static u32 builder_find_or_add_dir(RomfsBuilder* b, u32 parent_idx, const char* name, u32 name_len, bool dedup) {
    if (b->failed) return ROMFS_ENTRY_EMPTY;
    if (dedup) {
        for (u32 cur = b->dirs[parent_idx].first_child_dir; cur != ROMFS_ENTRY_EMPTY; cur = b->dirs[cur].next_sibling) {
            if (b->dirs[cur].name_len == name_len &&
                memcmp(b->name_pool + b->dirs[cur].name_off, name, name_len) == 0) {
                return cur;
            }
        }
    }
#ifdef NUPVFS_PLUGIN
    if (b->dir_count >= VFS_MAX_DIRS) { b->failed = true; return ROMFS_ENTRY_EMPTY; }
#endif
    if (b->dir_count >= b->dir_cap) {
        const u32 ncap = next_growth_cap(b->dir_cap, 256u, b->dir_count + 1u);
        BuildDir* nd = (BuildDir*)realloc(b->dirs, (size_t)ncap * sizeof(BuildDir));
        if (!nd) { b->failed = true; return ROMFS_ENTRY_EMPTY; }
        b->dirs = nd;
        b->dir_cap = ncap;
    }
    const u32 idx = b->dir_count++;
    BuildDir* d = &b->dirs[idx];
    memset(d, 0, sizeof(*d));
    d->parent_idx = parent_idx;
    d->first_child_dir = ROMFS_ENTRY_EMPTY;
    d->first_file = ROMFS_ENTRY_EMPTY;
    d->hash_next = ROMFS_ENTRY_EMPTY;
    d->name_off = pool_append(&b->name_pool, &b->name_used, &b->name_cap, name, name_len, 0, &b->failed);
    d->name_len = name_len;
    d->next_sibling = b->dirs[parent_idx].first_child_dir;
    b->dirs[parent_idx].first_child_dir = idx;
    return idx;
}

static void builder_delete_file(RomfsBuilder* b, u32 parent_idx,
                                const char* name, u32 name_len) {
    u32 prev = ROMFS_ENTRY_EMPTY;
    for (u32 cur = b->dirs[parent_idx].first_file; cur != ROMFS_ENTRY_EMPTY; cur = b->files[cur].next_sibling) {
        if (b->files[cur].name_len == name_len &&
            memcmp(b->name_pool + b->files[cur].name_off, name, name_len) == 0) {
            if (prev == ROMFS_ENTRY_EMPTY)
                b->dirs[parent_idx].first_file = b->files[cur].next_sibling;
            else
                b->files[prev].next_sibling = b->files[cur].next_sibling;
            b->files[cur].deleted = 1;
            b->files[cur].next_sibling = ROMFS_ENTRY_EMPTY;
            b->layer_deleted++;
            return;
        }
        prev = cur;
    }
}

static void builder_add_or_replace_file(RomfsBuilder* b, u32 parent_idx,
                                        const char* name, u32 name_len,
                                        const char* sd_path, u64 size, bool replace) {
    if (b->failed) return;
#ifdef NUPVFS_PLUGIN
    const u32 path_lim = VFS_MAX_PATH_POOL;
#else
    const u32 path_lim = 0;
#endif
    if (replace) {
        for (u32 cur = b->dirs[parent_idx].first_file; cur != ROMFS_ENTRY_EMPTY; cur = b->files[cur].next_sibling) {
            if (b->files[cur].name_len == name_len &&
                memcmp(b->name_pool + b->files[cur].name_off, name, name_len) == 0) {
                b->files[cur].sd_path_off = pool_append(&b->path_pool, &b->path_used, &b->path_cap,
                                                        sd_path, (u32)strlen(sd_path), path_lim, &b->failed);
                b->files[cur].size = size;
                b->layer_replaced++;
                return;
            }
        }
    }
#ifdef NUPVFS_PLUGIN
    if (b->file_count >= VFS_MAX_FILES) { b->failed = true; return; }
#endif
    if (b->file_count >= b->file_cap) {
        const u32 ncap = next_growth_cap(b->file_cap, 512u, b->file_count + 1u);
        BuildFile* nf = (BuildFile*)realloc(b->files, (size_t)ncap * sizeof(BuildFile));
        if (!nf) { b->failed = true; return; }
        b->files = nf;
        b->file_cap = ncap;
    }
    const u32 idx = b->file_count++;
    BuildFile* f = &b->files[idx];
    memset(f, 0, sizeof(*f));
    f->parent_idx = parent_idx;
    f->hash_next = ROMFS_ENTRY_EMPTY;
    f->name_off = pool_append(&b->name_pool, &b->name_used, &b->name_cap, name, name_len, 0, &b->failed);
    f->name_len = name_len;
    f->sd_path_off = pool_append(&b->path_pool, &b->path_used, &b->path_cap,
                                 sd_path, (u32)strlen(sd_path), path_lim, &b->failed);
    f->size = size;
    f->next_sibling = b->dirs[parent_idx].first_file;
    b->dirs[parent_idx].first_file = idx;
    if (replace)
        b->layer_added++;
}

static void walk_sd_tree(RomfsBuilder* b, const char* root_path, bool replace) {
    if (b->failed)
        return;
    WalkWorkItem* stack = (WalkWorkItem*)malloc(256 * sizeof(WalkWorkItem));
    if (!stack) {
        b->failed = true;
        return;
    }
    u32 sp = 0, scap = 256;
    const u32 root_off = pool_append(&b->dir_path_pool, &b->dir_path_used, &b->dir_path_cap,
                                     root_path, (u32)strlen(root_path), 0, &b->failed);
    if (!b->failed) {
        stack[sp++] = (WalkWorkItem){ .dir_idx = 0, .dir_path_off = root_off, .depth = 0 };
    }

    char cur_dir[FS_MAX_PATH];
    char child_path[FS_MAX_PATH];

    while (sp > 0 && !b->failed) {
        const WalkWorkItem it = stack[--sp];
        if (it.depth > 32)
            continue;
        snprintf(cur_dir, sizeof(cur_dir), "%s", b->dir_path_pool + it.dir_path_off);

        FsDir dir = {};
        if (R_FAILED(nupRawFsOpenDir(b->sd, cur_dir, FsDirOpenMode_ReadDirs | FsDirOpenMode_ReadFiles, &dir)))
            continue;

        b->dirs_visited++;
        if (g_progress_cb && (b->dirs_visited == 1u || (b->dirs_visited & 511u) == 0u))
            g_progress_cb(b->dir_count, b->file_count);

        s64 got = 0;
        while (!b->failed && R_SUCCEEDED(nupRawDirRead(&dir, &got, b->ents, VFS_DIR_BATCH)) && got > 0) {
            for (s64 i = 0; i < got && !b->failed; i++) {
                const char* name = b->ents[i].name;
                if (!name[0] || (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))))
                    continue;
                const u32 nlen = (u32)strlen(name);
                if (strcmp(cur_dir, "/") == 0)
                    snprintf(child_path, sizeof(child_path), "/%s", name);
                else
                    snprintf(child_path, sizeof(child_path), "%.500s/%.250s", cur_dir, name);

                if (b->ents[i].type == FsDirEntryType_Dir) {
                    const u32 didx = builder_find_or_add_dir(b, it.dir_idx, name, nlen, replace);
                    if (didx == ROMFS_ENTRY_EMPTY)
                        break;
                    if (sp >= scap) {
                        const u32 ncap = scap * 2u;
                        WalkWorkItem* ns = (WalkWorkItem*)realloc(stack, (size_t)ncap * sizeof(WalkWorkItem));
                        if (!ns) { b->failed = true; break; }
                        stack = ns;
                        scap = ncap;
                    }
                    const u32 poff = pool_append(&b->dir_path_pool, &b->dir_path_used, &b->dir_path_cap,
                                                 child_path, (u32)strlen(child_path), 0, &b->failed);
                    if (!b->failed)
                        stack[sp++] = (WalkWorkItem){ .dir_idx = didx, .dir_path_off = poff, .depth = it.depth + 1u };
                } else {
                    if (replace && nlen > 5 && memcmp(name + nlen - 5, ".stub", 5) == 0) {
                        builder_delete_file(b, it.dir_idx, name, nlen - 5);
                    } else {
                        builder_add_or_replace_file(b, it.dir_idx, name, nlen, child_path,
                                                    (u64)b->ents[i].file_size, replace);
                    }
                }
            }
        }
        serviceClose(&dir.s);
    }
    free(stack);
}

static void wr32_le(u8* p, u32 v) { memcpy(p, &v, 4); }
static void wr64_le(u8* p, u64 v) { memcpy(p, &v, 8); }

bool vfsRomfsBuildLayered(VfsRomfs* r, FsFileSystem* sd,
                          const char* sd_root,
                          const char* const* overlays, int overlay_count) {
    memset(r, 0, sizeof(*r));
    nupSpinInit(&r->lru_lock);
    if (!sd || !sd_root || !sd_root[0])
        return false;

    u32 et = 0;
    if (R_FAILED(nupRawFsGetEntryType(sd, sd_root, &et)) || et != FsDirEntryType_Dir)
        return false;

    RomfsBuilder b = {};
    b.sd = sd;
    // Root directory entry (index 0, empty name, parent = 0)
    b.dirs = (BuildDir*)calloc(256, sizeof(BuildDir));
    b.ents = (FsDirectoryEntry*)malloc(VFS_DIR_BATCH * sizeof(FsDirectoryEntry));
    if (!b.dirs || !b.ents) {
        free(b.dirs);
        free(b.ents);
        return false;
    }
    b.dir_cap = 256;
    b.dir_count = 1;
    b.dirs[0].parent_idx = 0;
    b.dirs[0].first_child_dir = ROMFS_ENTRY_EMPTY;
    b.dirs[0].next_sibling = ROMFS_ENTRY_EMPTY;
    b.dirs[0].first_file = ROMFS_ENTRY_EMPTY;
    b.dirs[0].hash_next = ROMFS_ENTRY_EMPTY;
    b.dirs[0].name_off = pool_append(&b.name_pool, &b.name_used, &b.name_cap, "", 0, 0, &b.failed);
    b.dirs[0].name_len = 0;

    walk_sd_tree(&b, sd_root, false);
    for (int oi = 0; oi < overlay_count && !b.failed; oi++) {
        const char* ov = overlays ? overlays[oi] : NULL;
        if (ov && ov[0] && R_SUCCEEDED(nupRawFsGetEntryType(sd, ov, &et)) && et == FsDirEntryType_Dir) {
            b.layer_added = 0;
            b.layer_replaced = 0;
            b.layer_deleted = 0;
            walk_sd_tree(&b, ov, true);
            nupLogf("[romfs] overlay layer[%d]: %s (replaced=%u added=%u deleted=%u)\n",
                    oi, ov, b.layer_replaced, b.layer_added, b.layer_deleted);
        }
    }
    // Free walk-only scratch buffers BEFORE allocating final RomFS metadata/spans
    free(b.ents);
    b.ents = NULL;
    free(b.dir_path_pool);
    b.dir_path_pool = NULL;
    if (g_progress_cb && !b.failed)
        g_progress_cb(b.dir_count, b.file_count);
    if (b.failed) {
        free(b.dirs);
        free(b.files);
        free(b.name_pool);
        free(b.path_pool);
        return false;
    }

    // 1. Assign table offsets for directories and files
    u32 dir_table_sz = 0;
    for (u32 i = 0; i < b.dir_count; i++) {
        b.dirs[i].table_off = dir_table_sz;
        dir_table_sz += ROMFS_DIR_HDR_SZ + align4_u32(b.dirs[i].name_len);
    }
    u32 file_table_sz = 0;
    u32 active_files = 0;
    u64 data_cursor = 0;
    for (u32 i = 0; i < b.file_count; i++) {
        if (b.files[i].deleted)
            continue;
        b.files[i].table_off = file_table_sz;
        file_table_sz += ROMFS_FILE_HDR_SZ + align4_u32(b.files[i].name_len);
        b.files[i].data_off = data_cursor;
        data_cursor = align16_u64(data_cursor + b.files[i].size);
        active_files++;
    }

    const u32 dir_buckets = romfs_hash_bucket_count(b.dir_count);
    const u32 file_buckets = romfs_hash_bucket_count(active_files);
    const u64 dir_hash_off = ROMFS_HEADER_SIZE;
    const u64 dir_hash_sz = (u64)dir_buckets * 4ull;
    const u64 dir_table_off = dir_hash_off + dir_hash_sz;
    const u64 file_hash_off = dir_table_off + dir_table_sz;
    const u64 file_hash_sz = (u64)file_buckets * 4ull;
    const u64 file_table_off = file_hash_off + file_hash_sz;
    const u64 file_data_off = align16_u64(file_table_off + file_table_sz);

    u8* meta = (u8*)calloc(1, (size_t)file_data_off);
    VfsRomfsSpan* spans = active_files ? (VfsRomfsSpan*)malloc((size_t)active_files * sizeof(VfsRomfsSpan)) : NULL;
    if (!meta || (active_files && !spans)) {
        free(meta);
        free(spans);
        free(b.dirs);
        free(b.files);
        free(b.name_pool);
        free(b.path_pool);
        return false;
    }

    // 2. Write header
    RomfsBinHeader hdr = {
        .header_size = ROMFS_HEADER_SIZE,
        .dir_hash_off = dir_hash_off,
        .dir_hash_size = dir_hash_sz,
        .dir_table_off = dir_table_off,
        .dir_table_size = dir_table_sz,
        .file_hash_off = file_hash_off,
        .file_hash_size = file_hash_sz,
        .file_table_off = file_table_off,
        .file_table_size = file_table_sz,
        .file_data_off = file_data_off,
    };
    memcpy(meta, &hdr, sizeof(hdr));

    // 3. Populate directory hash table & directory metadata table
    u32* dhash = (u32*)(meta + dir_hash_off);
    for (u32 i = 0; i < dir_buckets; i++) dhash[i] = ROMFS_ENTRY_EMPTY;
    for (u32 i = 0; i < b.dir_count; i++) {
        const u32 p_off = b.dirs[b.dirs[i].parent_idx].table_off;
        const u32 h = romfs_calc_hash(p_off, b.name_pool + b.dirs[i].name_off, b.dirs[i].name_len) % dir_buckets;
        b.dirs[i].hash_next = dhash[h];
        dhash[h] = b.dirs[i].table_off;
    }
    for (u32 i = 0; i < b.dir_count; i++) {
        const BuildDir* d = &b.dirs[i];
        u8* dst = meta + dir_table_off + d->table_off;
        wr32_le(dst + 0x00, b.dirs[d->parent_idx].table_off);
        wr32_le(dst + 0x04, d->next_sibling == ROMFS_ENTRY_EMPTY ? ROMFS_ENTRY_EMPTY : b.dirs[d->next_sibling].table_off);
        wr32_le(dst + 0x08, d->first_child_dir == ROMFS_ENTRY_EMPTY ? ROMFS_ENTRY_EMPTY : b.dirs[d->first_child_dir].table_off);
        wr32_le(dst + 0x0C, d->first_file == ROMFS_ENTRY_EMPTY ? ROMFS_ENTRY_EMPTY : b.files[d->first_file].table_off);
        wr32_le(dst + 0x10, d->hash_next);
        wr32_le(dst + 0x14, d->name_len);
        if (d->name_len) memcpy(dst + 0x18, b.name_pool + d->name_off, d->name_len);
    }

    // 4. Populate file hash table, file metadata table, and sorted file spans
    u32* fhash = (u32*)(meta + file_hash_off);
    for (u32 i = 0; i < file_buckets; i++) fhash[i] = ROMFS_ENTRY_EMPTY;
    for (u32 i = 0; i < b.file_count; i++) {
        if (b.files[i].deleted)
            continue;
        const u32 p_off = b.dirs[b.files[i].parent_idx].table_off;
        const u32 h = romfs_calc_hash(p_off, b.name_pool + b.files[i].name_off, b.files[i].name_len) % file_buckets;
        b.files[i].hash_next = fhash[h];
        fhash[h] = b.files[i].table_off;
    }
    u32 span_i = 0;
    for (u32 i = 0; i < b.file_count; i++) {
        const BuildFile* f = &b.files[i];
        if (f->deleted)
            continue;
        u8* dst = meta + file_table_off + f->table_off;
        wr32_le(dst + 0x00, b.dirs[f->parent_idx].table_off);
        wr32_le(dst + 0x04, f->next_sibling == ROMFS_ENTRY_EMPTY ? ROMFS_ENTRY_EMPTY : b.files[f->next_sibling].table_off);
        wr64_le(dst + 0x08, f->data_off);
        wr64_le(dst + 0x10, f->size);
        wr32_le(dst + 0x18, f->hash_next);
        wr32_le(dst + 0x1C, f->name_len);
        if (f->name_len) memcpy(dst + 0x20, b.name_pool + f->name_off, f->name_len);

        spans[span_i].data_off = f->data_off;
        spans[span_i].size = f->size;
        spans[span_i].path_off = f->sd_path_off;
        spans[span_i].pad = 0;
        span_i++;
    }

    free(b.dirs);
    free(b.files);
    free(b.name_pool);

    r->sd = sd;
    r->meta_buf = meta;
    r->file_data_off = file_data_off;
    r->total_size = file_data_off + data_cursor;
    r->spans = spans;
    r->span_count = active_files;
    r->span_cap = active_files;
    r->path_pool = b.path_pool;
    r->path_used = b.path_used;
    r->path_cap = b.path_cap;
    r->ready = true;

    nupLogf("[romfs] virtual IStorage built for '%s': dirs=%u files=%u meta=%lluB total=%lluB\n",
            sd_root, (unsigned)(dir_table_sz / ROMFS_DIR_HDR_SZ), r->span_count,
            (unsigned long long)r->file_data_off, (unsigned long long)r->total_size);
    return true;
}

bool vfsRomfsBuild(VfsRomfs* r, FsFileSystem* sd,
                   const char* sd_root, const char* sd_overlay) {
    const char* ovs[1] = { sd_overlay };
    return vfsRomfsBuildLayered(r, sd, sd_root, ovs, (sd_overlay && sd_overlay[0]) ? 1 : 0);
}

void vfsRomfsDestroy(VfsRomfs* r) {
    if (!r) return;
    for (int i = 0; i < VFS_ROMFS_LRU_SLOTS; i++) {
        if (r->lru[i].in_use) {
            serviceClose(&r->lru[i].file.s);
            r->lru[i].in_use = false;
        }
    }
    free(r->meta_buf);
    free(r->spans);
    free(r->path_pool);
    memset(r, 0, sizeof(*r));
}

static u32 find_span_for_rel(const VfsRomfs* r, u64 rel) {
    if (r->span_count == 0)
        return ROMFS_ENTRY_EMPTY;
    u32 lo = 0, hi = r->span_count;
    while (lo < hi) {
        const u32 mid = lo + (hi - lo) / 2u;
        if (r->spans[mid].data_off <= rel)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return (lo > 0) ? (lo - 1u) : ROMFS_ENTRY_EMPTY;
}

static Result read_span_from_sd(VfsRomfs* r, u32 span_idx, u64 file_off, u8* dst, u64 want) {
    // Check LRU cache under spinlock; read with lock held or re-open on miss
    nupSpinLock(&r->lru_lock);
    int slot = -1;
    int empty = -1;
    int oldest = 0;
    for (int i = 0; i < VFS_ROMFS_LRU_SLOTS; i++) {
        if (r->lru[i].in_use) {
            if (r->lru[i].span_idx == span_idx) {
                slot = i;
                break;
            }
            if (!r->lru[oldest].in_use || r->lru[i].last_use < r->lru[oldest].last_use)
                oldest = i;
        } else if (empty < 0) {
            empty = i;
        }
    }
    if (slot < 0) {
        const char* path = r->path_pool + r->spans[span_idx].path_off;
        FsFile nf = {};
        const Result orc = nupRawFsOpenFile(r->sd, path, FsOpenMode_Read, &nf);
        if (R_FAILED(orc)) {
            nupSpinUnlock(&r->lru_lock);
            return orc;
        }
        slot = (empty >= 0) ? empty : oldest;
        if (r->lru[slot].in_use)
            serviceClose(&r->lru[slot].file.s);
        r->lru[slot].in_use = true;
        r->lru[slot].span_idx = span_idx;
        r->lru[slot].file = nf;
    }
    r->lru[slot].last_use = ++r->lru_clock;

    u64 done = 0;
    Result rc = 0;
    while (done < want) {
        const u64 chunk = (want - done) > 0x400000ull ? 0x400000ull : (want - done);
        u64 got = 0;
        rc = nupRawFileRead(&r->lru[slot].file, (s64)(file_off + done), dst + done, chunk, &got);
        if (R_FAILED(rc)) break;
        done += got;
        if (got < chunk) {
            if (done < want)
                memset(dst + done, 0, (size_t)(want - done));
            break;
        }
    }
    nupSpinUnlock(&r->lru_lock);
    return rc;
}

Result vfsRomfsRead(VfsRomfs* r, u64 offset, void* dst, u64 size, u64* out_got) {
    if (out_got) *out_got = 0;
    if (!r || !r->ready || !dst)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (size == 0 || offset >= r->total_size)
        return 0;

    u64 remain = size;
    if (offset + remain > r->total_size)
        remain = r->total_size - offset;

    u8* out = (u8*)dst;
    u64 cur = offset;
    u64 total_read = 0;

    // 1. Metadata region [0 .. file_data_off)
    if (cur < r->file_data_off) {
        u64 n = r->file_data_off - cur;
        if (n > remain) n = remain;
        memcpy(out, r->meta_buf + cur, (size_t)n);
        out += n;
        cur += n;
        remain -= n;
        total_read += n;
    }

    // 2. File data region [file_data_off .. total_size)
    while (remain > 0) {
        const u64 rel = cur - r->file_data_off;
        const u32 idx = find_span_for_rel(r, rel);
        if (idx == ROMFS_ENTRY_EMPTY) {
            memset(out, 0, (size_t)remain);
            total_read += remain;
            break;
        }
        const VfsRomfsSpan* sp = &r->spans[idx];
        const u64 sp_end = sp->data_off + sp->size;
        if (rel < sp_end) {
            u64 n = sp_end - rel;
            if (n > remain) n = remain;
            const Result rc = read_span_from_sd(r, idx, rel - sp->data_off, out, n);
            if (R_FAILED(rc)) {
                if (out_got) *out_got = total_read;
                return rc;
            }
            out += n;
            cur += n;
            remain -= n;
            total_read += n;
        } else {
            // Alignment padding between sp_end and next span
            const u64 next_off = (idx + 1u < r->span_count) ? r->spans[idx + 1u].data_off : (r->total_size - r->file_data_off);
            u64 pad = (next_off > rel) ? (next_off - rel) : remain;
            if (pad > remain) pad = remain;
            memset(out, 0, (size_t)pad);
            out += pad;
            cur += pad;
            remain -= pad;
            total_read += pad;
        }
    }

    if (out_got) *out_got = total_read;
    return 0;
}
