// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <switch.h>

#define MAX_NUP_ENTRIES 64

typedef struct {
    char label[0x60];
    char path[0x400];
    u64 title_id;
    u32 exefs_count;
} NupEntry;

void nupUiScanAll(FsFileSystem* sd, NupEntry* entries, int* out_count,
                  char* skip_note, size_t skip_note_sz);
void nupUiDrawMenu(const NupEntry* entries, int count, int cursor,
                   const char* status, const char* skip_note);
bool nupUiReadAutolaunch(FsFileSystem* sd, NupEntry* out, bool* out_trace);
bool nupUiProbeArgv(FsFileSystem* sd, int argc, char** argv, NupEntry* out, bool* out_trace);
