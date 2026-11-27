// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <switch.h>

#include "compat_caps.h"
#include "nup.h"

void nupSvcHipcInit(NupArchive* nup, FsFileSystem* sd,
                    const NupRuntimeCapabilities* caps, Handle hen_sm_proxy);

void nupSvcHipcSetVfsPlugin(Handle vfs_session, u32 vfs_flags);

void nupSvcHipcSetNvHandle(Handle nv_session);

// Returns the highest heap address owned by pre-built VfsRomfs tables so
// shrink_libnx_heap_for_game() retains them safely below the game's heap.
u64 nupSvcHipcMaxHeapAddr(void);

// Called immediately after shrink_libnx_heap_for_game() so svcSetHeapSize / svcGetInfo
// transparently hide the loader's retained heap prefix from the target game.
void nupSvcHipcSetHostHeap(u64 heap_base, u64 host_keep);

// Mark heap allocated by Switch 1 CompatibilityPack before app startup so
// svcGetInfo(UsedMemorySize) excludes it from the Switch 1 app's own memory view.
void nupSvcHipcMarkCompatHeapEnd(void);

// Optional startup window toggle for capability-gated 1 MiB VAM probe capping in svc #0x2c.
void nupSvcHipcSetInStartup(bool in_startup);

// Called from svc_entry.s on a private 64 KiB handler stack.
// Returns 1 if handled (regs[0..7] populated), or 0 to pass through to real kernel SVC.
int nupSvcDispatch(u64* regs, u32 svc_num);
