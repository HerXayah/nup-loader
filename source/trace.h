// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <switch.h>

#include "elf_loader.h"

#define NUP_TRACE_MAX_SLOTS 2048u
#define NUP_TRACE_RING_SIZE 512u

void nupTraceReset(bool enabled);
bool nupTraceIsEnabled(void);
void nupTraceSetModules(const ModuleSet* set);

// Returns a trampoline address for a PLT import if tracing is enabled and the
// symbol matches our interesting-API filter (and a slot is available); 0 otherwise.
u64 nupTraceWrapPlt(const char* mod_name, const char* sym_name, u64 target_addr);

u32 nupTraceSlotCount(void);
u32 nupTraceTotalSeq(void);

// Called from heartbeat thread (1Hz) to flush newly-seen APIs and detect stalls.
void nupTracePollHeartbeat(u32 sec);

// Dumps the last `max_entries` calls from the lock-free ring buffer to the log.
void nupTraceDumpRecent(const char* reason, u32 max_entries);

// Called from trace_tramp.s (hot path: lock-free, zero-syscall, zero-TLS).
u64 nupTraceRecord(u32 slot_idx, u64 lr, u64 x0, u64 x1, u64 x2, u64 x3);
