// SPDX-License-Identifier: MIT
#pragma once

#include "compat_caps.h"
#include "elf_loader.h"
#include "nup.h"

void nupCollectRuntimeCaps(NupRuntimeCapabilities* caps, NupArchive* nup,
                           const NupFileInfo* exefs, u32 exefs_count,
                           const ModuleSet* mods, u64 target_tid);
void nupLogRuntimeCaps(const NupRuntimeCapabilities* caps);
