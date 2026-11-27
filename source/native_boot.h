// SPDX-License-Identifier: MIT
// Direct Native Loader Boot (HenHomebrewCommand_SetNextPackage) packer.
// Packs a game's real rtld+main+subsdk*+patched-sdk + /kaihen/bin/romfs-subsdk.nso
// + donor signed /kaihen/bin/game/main.npdm into one-shot /kaihen/bin/game/next.nsp.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <switch.h>

#include "ui.h"

Result nupArmNativeLoaderBoot(FsFileSystem* sd, const NupEntry* entry,
                              char* out_msg, size_t out_msg_sz);
