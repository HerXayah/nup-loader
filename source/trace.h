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

// Shared selection predicate used by both Static Audit (L) capacity reporting
// and Trace Launch (Y) trampoline allocation.
bool nupTraceShouldWrap(const char* mod_name, const char* sym_name);

// Allocates or reuses a trampoline slot for a resolved PLT/GLOB_DAT function
// pointer if tracing is enabled and the symbol is selected; returns 0 otherwise.
u64 nupTraceWrapPlt(const char* mod_name, const char* sym_name, u64 target_addr);

// Runtime lookup proxy for dynamic resolvers (e.g. nvnDeviceGetProcAddress).
// Allocates a trampoline for selected runtime-resolved procs when tracing is active.
u64 nupTraceWrapDynamicProc(const char* source, const char* proc_name, u64 target_addr);

u32 nupTraceSlotCount(void);
u32 nupTraceOverflowCount(void);
u64 nupTraceTotalSeq(void);
u64 nupTraceDroppedCount(void);

// Called periodically from the heartbeat/checkpoint thread to batch-drain newly
// committed ring entries to persistent storage and emit inactivity snapshots.
void nupTracePollHeartbeat(u32 elapsed_ms, bool boot_phase);

// Dumps the last `max_entries` calls from the lock-free ring buffer to the log.
void nupTraceDumpRecent(const char* reason, u32 max_entries);

// Called from trace_tramp.s (hot path: lock-free, zero-syscall, zero-TLS).
u64 nupTraceRecord(u32 slot_idx, u64 lr, u64 x0, u64 x1, u64 x2, u64 x3);
