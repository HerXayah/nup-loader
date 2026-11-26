// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <switch.h>

#define NUP_MAX_EXEFS_FILES 24
#define NUP_MAX_NAME 64
#define NUP_MAX_ROMFS_LAYERS 8

typedef struct {
    char name[NUP_MAX_NAME + 1];
    u64 size;
    u64 offset;
    u64 comp_size;
    u8 codec;
} NupFileInfo;

typedef struct {
    u64 title_id;
    u32 root_dir_idx;
    u32 exefs_dir_idx;
    u32 romfs_dir_idx;
    u32 version;
    u8 kind;
    u8 flags;
    u8 pad0[6];
    u64 meta_off;
    u32 meta_size;
    u32 pad1;
    u64 reserved[2];
} NupPartEntry;

_Static_assert(sizeof(NupPartEntry) == 0x40, "NupPartEntry size");

typedef struct {
    u32 name_off;
    u32 name_len;
    u32 first_child;
    u32 child_count;
    u32 reserved0;
    u32 reserved1;
} NupDirEntry;

_Static_assert(sizeof(NupDirEntry) == 0x18, "NupDirEntry size");

typedef struct {
    u32 name_off;
    u32 name_len;
    u64 size;
    u64 data_off;
    u64 comp_size;
    u8 sha256[32];
    u8 codec;
    u8 pad0[15];
} NupFileEntry;

_Static_assert(sizeof(NupFileEntry) == 0x50, "NupFileEntry size");

typedef struct {
    volatile int locked;
} NupSpinLock;

static inline void nupSpinInit(NupSpinLock* l) {
    __atomic_store_n(&l->locked, 0, __ATOMIC_RELAXED);
}

static inline void nupSpinLock(NupSpinLock* l) {
    while (__atomic_exchange_n(&l->locked, 1, __ATOMIC_ACQUIRE))
        svcSleepThread(1000000ULL);
}

static inline void nupSpinUnlock(NupSpinLock* l) {
    __atomic_store_n(&l->locked, 0, __ATOMIC_RELEASE);
}

// TLS-safe raw FS IPC helpers (safe to call from game-created nn::os threads
// that do not have libnx ThreadVars / __aarch64_read_tp initialized).
static inline Result nupRawFileRead(FsFile* f, s64 offset, void* dst, u64 size, u64* out_read) {
    const struct {
        u32 option;
        u32 pad;
        s64 offset;
        u64 size;
    } in = { FsReadOption_None, 0, offset, size };
    return serviceDispatchInOut(&f->s, 0, in, *out_read,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out | SfBufferAttr_HipcMapTransferAllowsNonSecure },
        .buffers = { { dst, size } });
}

static inline Result nupRawFileWrite(FsFile* f, s64 offset, const void* src, u64 size, u32 option) {
    const struct {
        u32 option;
        u32 pad;
        s64 offset;
        u64 size;
    } in = { option, 0, offset, size };
    return serviceDispatchIn(&f->s, 1, in,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In | SfBufferAttr_HipcMapTransferAllowsNonSecure },
        .buffers = { { src, size } });
}

static inline Result nupRawFsCommit(FsFileSystem* fs) {
    return serviceDispatch(&fs->s, 10);
}

static inline Result nupRawFsGetEntryType(FsFileSystem* fs, const char* path, u32* out_type) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatchOut(&fs->s, 7, *out_type,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsOpenFile(FsFileSystem* fs, const char* path, u32 mode, FsFile* out) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatchIn(&fs->s, 8, mode,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } },
        .out_num_objects = 1,
        .out_objects = &out->s);
}

static inline Result nupRawFsOpenDir(FsFileSystem* fs, const char* path, u32 mode, FsDir* out) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatchIn(&fs->s, 9, mode,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } },
        .out_num_objects = 1,
        .out_objects = &out->s);
}

static inline Result nupRawFileFlush(FsFile* f) {
    return serviceDispatch(&f->s, 2);
}

static inline Result nupRawFileSetSize(FsFile* f, s64 size) {
    return serviceDispatchIn(&f->s, 3, size);
}

static inline Result nupRawFileGetSize(FsFile* f, s64* out_size) {
    return serviceDispatchOut(&f->s, 4, *out_size);
}

static inline Result nupRawFsCreateFile(FsFileSystem* fs, const char* path, s64 size, u32 option) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    const struct {
        u32 option;
        u32 pad;
        s64 size;
    } in = { option, 0, size };
    return serviceDispatchIn(&fs->s, 0, in,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsDeleteFile(FsFileSystem* fs, const char* path) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatch(&fs->s, 1,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsCreateDir(FsFileSystem* fs, const char* path) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatch(&fs->s, 2,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsDeleteDir(FsFileSystem* fs, const char* path) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatch(&fs->s, 3,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsDeleteDirRec(FsFileSystem* fs, const char* path) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatch(&fs->s, 4,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsRenameFile(FsFileSystem* fs, const char* cur_path, const char* new_path) {
    char p1[FS_MAX_PATH], p2[FS_MAX_PATH];
    memset(p1, 0, sizeof(p1));
    memset(p2, 0, sizeof(p2));
    strncpy(p1, cur_path, sizeof(p1) - 1);
    strncpy(p2, new_path, sizeof(p2) - 1);
    return serviceDispatch(&fs->s, 5,
        .buffer_attrs = {
            SfBufferAttr_HipcPointer | SfBufferAttr_In,
            SfBufferAttr_HipcPointer | SfBufferAttr_In,
        },
        .buffers = {
            { p1, FS_MAX_PATH },
            { p2, FS_MAX_PATH },
        });
}

static inline Result nupRawFsRenameDir(FsFileSystem* fs, const char* cur_path, const char* new_path) {
    char p1[FS_MAX_PATH], p2[FS_MAX_PATH];
    memset(p1, 0, sizeof(p1));
    memset(p2, 0, sizeof(p2));
    strncpy(p1, cur_path, sizeof(p1) - 1);
    strncpy(p2, new_path, sizeof(p2) - 1);
    return serviceDispatch(&fs->s, 6,
        .buffer_attrs = {
            SfBufferAttr_HipcPointer | SfBufferAttr_In,
            SfBufferAttr_HipcPointer | SfBufferAttr_In,
        },
        .buffers = {
            { p1, FS_MAX_PATH },
            { p2, FS_MAX_PATH },
        });
}

static inline Result nupRawFsGetFreeSpace(FsFileSystem* fs, const char* path, s64* out_size) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatchOut(&fs->s, 11, *out_size,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsGetTotalSpace(FsFileSystem* fs, const char* path, s64* out_size) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatchOut(&fs->s, 12, *out_size,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawFsCleanDirRec(FsFileSystem* fs, const char* path) {
    char pbuf[FS_MAX_PATH];
    memset(pbuf, 0, sizeof(pbuf));
    strncpy(pbuf, path, sizeof(pbuf) - 1);
    return serviceDispatch(&fs->s, 13,
        .buffer_attrs = { SfBufferAttr_HipcPointer | SfBufferAttr_In },
        .buffers = { { pbuf, FS_MAX_PATH } });
}

static inline Result nupRawDirRead(FsDir* d, s64* out_cnt, FsDirectoryEntry* buf, u64 max_cnt) {
    return serviceDispatchOut(&d->s, 0, *out_cnt,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers = { { buf, max_cnt * sizeof(FsDirectoryEntry) } });
}

static inline Result nupRawDirGetEntryCount(FsDir* d, s64* out_cnt) {
    return serviceDispatchOut(&d->s, 1, *out_cnt);
}

typedef struct {
    bool is_raw;
    FsFileSystem* raw_sd;
    char raw_app_root[0x300];
    char raw_root[0x300];

    FsFile file;
    bool open;
    NupSpinLock io_lock;

    u64 toc_off;
    u64 toc_size;
    u32 part_count;
    u64 dir_count;
    u64 file_count;
    u64 str_off;
    u64 str_size;
    u64 title_id;

    u8* toc_buf;
    const NupPartEntry* parts;
    const NupDirEntry* dirs;
    const NupFileEntry* files;
    const u32* children;
    const char* strings;
    u32 romfs_dir_idx;
    u32 romfs_dirs[NUP_MAX_ROMFS_LAYERS];
    u32 romfs_layer_count;
    bool has_romfs;
    u32 dlc_dir_idx;
    bool has_dlc;
} NupArchive;

const char* nupLastProbeError(void);

bool nupProbe(FsFileSystem* sd, const char* path, u64* out_title_id,
              NupFileInfo* out_exefs, u32* out_exefs_count);
bool nupProbeRaw(FsFileSystem* sd, const char* dir_path, u64* out_title_id,
                 NupFileInfo* out_exefs, u32* out_exefs_count);
Result nupOpenFull(NupArchive* nup, FsFileSystem* sd, const char* path);
Result nupOpenRaw(NupArchive* nup, FsFileSystem* sd, const char* dir_path);
void nupClose(NupArchive* nup);
bool nupLookupInDir(const NupArchive* nup, u32 root_dir_idx, const char* rel_path,
                    bool* out_is_dir, u32* out_idx);
bool nupLookupRomfs(const NupArchive* nup, const char* rel_path,
                    bool* out_is_dir, u32* out_idx);
Result nupReadFile(NupArchive* nup, u32 file_idx, s64 offset, void* dst,
                   size_t size, size_t* out_read);
Result nupReadRaw(NupArchive* nup, u64 offset, void* dst, size_t size);
Result nupReadExefs(NupArchive* nup, const NupFileInfo* fi, u64 offset, void* dst, size_t size);
void nupFormatRawRomPath(const NupArchive* nup, const char* rel_path, char* out, size_t out_sz);
