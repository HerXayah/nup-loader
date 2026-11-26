// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <switch.h>

#include "compat_caps.h"
#include "nup.h"

typedef enum {
    HOOK_PROV_NONE = 0,
    HOOK_PROV_FS,       // RomFS / Saves / Cache / Temp / BCAT / File & Dir VFS
    HOOK_PROV_AOC,      // SD DLC / AddOnContent provider
    HOOK_PROV_MEM,      // Synchronized Heap / QueryMemoryInfo / VAM memory provider
    HOOK_PROV_ALLOC,    // StandardAllocator capability-gated provider
    HOOK_PROV_RTLD,     // nn::ro dynamic symbol lookup & compat chaining provider
    HOOK_PROV_SVC,      // SM proxy / VI / NVN / Boot & Abort diagnostics
} HookProviderKind;

void hooksInit(NupArchive* nup, FsFileSystem* sd,
               const NupRuntimeCapabilities* caps, Handle hen_sm_proxy);
void hooksSetNvHandle(Handle nv_session);

// Interposition resolver: looks up sym_name in the unified provider registry,
// binds real_addr into the provider's original-symbol slot when real_addr != 0,
// and returns the interposed hook address (or 0 if native SDK handles it).
u64 hooksResolve(const char* sym_name, u64 real_addr);

// Pure metadata query (never mutates original-symbol slots): returns the provider
// handling sym_name, and optionally whether it is safe as a terminal compat hook.
HookProviderKind hooksQueryProvider(const char* sym_name, bool* out_terminal_for_compat);
const char* hooksProviderName(HookProviderKind kind);

// Caller-aware LookupNextSymbolForCompat: resolves original symbol strictly after
// the calling module, substituting only terminal virtualized providers.
u32 hooksLookupNextForCompat(uintptr_t* out_addr, const char* sym_name);
