// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <switch.h>

#include "nup.h"

#define VFS_ROMFS_LRU_SLOTS 16

typedef struct {
    u64 data_off;      // Offset within RomFS fileDataOff region (relative to header.fileDataOff)
    u64 size;
    u32 path_off;      // Offset into path_pool
    u32 pad;
} VfsRomfsSpan;

typedef struct {
    bool in_use;
    u32 span_idx;
    u64 last_use;
    FsFile file;
} VfsRomfsLruEntry;

typedef struct {
    bool ready;
    u32 remote_slot;      // Non-zero when served by resident /kaihen/plugins/nupvfs.nso
    FsFileSystem* sd;
    u8* meta_buf;         // [0 .. file_data_off): header + 4 RomFS hash/meta tables
    u64 file_data_off;    // Aligned start of file data (== meta buffer size)
    u64 total_size;       // file_data_off + total aligned file data
    VfsRomfsSpan* spans;  // Sorted by data_off ascending
    u32 span_count;
    u32 span_cap;
    char* path_pool;      // NUL-terminated full SD paths
    u32 path_used;
    u32 path_cap;
    NupSpinLock lru_lock;
    u64 lru_clock;
    VfsRomfsLruEntry lru[VFS_ROMFS_LRU_SLOTS];
} VfsRomfs;

typedef void (*VfsRomfsProgressFn)(u32 dirs, u32 files);

void vfsRomfsSetProgressCallback(VfsRomfsProgressFn fn);

// Build an in-memory RomFS header + tables from an unpacked SD directory
// with ordered overlay directories (each later overlay shadows earlier ones).
// File contents stay on SD and are read lazily on demand via vfsRomfsRead().
bool vfsRomfsBuildLayered(VfsRomfs* r, FsFileSystem* sd,
                          const char* sd_root,
                          const char* const* overlays, int overlay_count);

bool vfsRomfsBuild(VfsRomfs* r, FsFileSystem* sd,
                   const char* sd_root, const char* sd_overlay);

void vfsRomfsDestroy(VfsRomfs* r);

Result vfsRomfsRead(VfsRomfs* r, u64 offset, void* dst, u64 size, u64* out_got);

static inline u64 vfsRomfsSize(const VfsRomfs* r) {
    return (r && r->ready) ? r->total_size : 0;
}
