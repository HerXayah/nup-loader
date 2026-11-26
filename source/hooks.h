// SPDX-License-Identifier: MIT
#pragma once

#include <stdint.h>
#include <switch.h>

#include "nup.h"

void hooksInit(NupArchive* nup, FsFileSystem* sd, u64 title_id, Handle hen_sm_proxy);
void hooksSetNvHandle(Handle nv_session);
u64 hooksResolve(const char* sym_name, u64 real_addr);
u32 hooksLookupNextForCompat(uintptr_t* out_addr, const char* sym_name);
