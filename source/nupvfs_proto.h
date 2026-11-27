// SPDX-License-Identifier: MIT
// Shared IPC protocol between resident kaiHEN plugin (/kaihen/plugins/nupvfs.nso)
// and clients (nup-loader.nro, romfs-subsdk.nso).
#pragma once

#include <switch/types.h>

#define NUPVFS_PLUGIN_NAME "nupvfs"
#define NUPVFS_MAGIC       0x56465331u /* "VFS1" */
#define NUPVFS_VERSION     1u
#define NUPVFS_MAX_SLOTS   16u
#define NUPVFS_MAX_LAYERS  6u
#define NUPVFS_PATH_MAX    0x300u

// Feature / settings bitflags shared with ounce-hbmenu Settings -> Plugins
#define NUPVFS_FLAG_MODS    (1u << 0) /* LayeredFS overlays enabled */
#define NUPVFS_FLAG_TRACE   (1u << 1) /* Force Trace Launch on headless boot */
#define NUPVFS_FLAG_CACHE   (1u << 2) /* Keep RomFS tables cached across launches */
#define NUPVFS_FLAG_NATIVE       (1u << 3) /* Prefer direct native Loader boot (SetNextPackage) */
#define NUPVFS_FLAG_CBUTTON      (1u << 4) /* GameChat C button arms/launches HBMenu */
#define NUPVFS_FLAG_HBMENU_GAMES (1u << 5) /* Auto-list RAW backup games directly in ounce-hbmenu */

// Custom kaiHEN HEN homebrew commands (matched in civ7-fs-kaihen/kaihen protocol.h)
#ifndef HEN_CMD_SET_NEXT_PACKAGE
#define HEN_CMD_SET_NEXT_PACKAGE    28u
#define HEN_CMD_CLEAR_NEXT_PACKAGE  29u
#define HEN_CMD_ARM_NEXT_LAUNCH     30u
#endif

// Must match HenNextPackagePath in kaihen/protocol.h
#define HEN_NEXT_PACKAGE_PATH_SIZE 128u

typedef struct {
    u8 auto_arm;                              /* 1 = auto-arm next launch without holding R */
    u8 reserved[3];
    char path[HEN_NEXT_PACKAGE_PATH_SIZE];    /* e.g. "@Sdcard:/kaihen/bin/game/next.nsp" */
} NupHenNextPackage;

typedef enum {
    // Out: NupVfsInfo
    NupVfsCmd_GetInfo       = 1,
    // In: NupVfsMountReq + A-buf (concatenated NUL-terminated layer paths)
    // Out: NupVfsMountReply
    NupVfsCmd_MountRomfs    = 2,
    // In: NupVfsReadReq + B-buf (destination bytes)
    // Out: u64 bytes_read
    NupVfsCmd_ReadRomfs     = 3,
    // In: none -> clears all cached RomFS slots
    NupVfsCmd_ClearCache    = 4,
    // In: NupVfsActiveGame + A-buf (NUL-terminated SD root path)
    NupVfsCmd_SetActiveGame = 5,
    // Out: NupVfsActiveGame + B-buf (NUL-terminated SD root path)
    NupVfsCmd_GetActiveGame = 6,
} NupVfsCmd;

typedef struct {
    u32 magic;
    u32 version;
    u32 slot_count;
    u32 flags;
    u32 cbutton_events;
    u32 cbutton_rc;
} NupVfsInfo;

typedef struct {
    u64 title_id;
    u32 prog_idx;
    u32 num_layers;
} NupVfsMountReq;

typedef struct {
    u32 slot_id;
    u32 cached;
    u64 total_size;
} NupVfsMountReply;

typedef struct {
    u32 slot_id;
    u32 pad;
    u64 offset;
    u64 size;
} NupVfsReadReq;

typedef struct {
    u64 title_id;
    u32 prog_idx;
    u32 flags;
} NupVfsActiveGame;
