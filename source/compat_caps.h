// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <switch.h>

typedef struct {
    // Measured donor host process capabilities (from current host SVCs)
    u64 donor_pid;
    u64 donor_mem_total;
    u64 donor_mem_used;
    u64 donor_sysres_total;
    u64 donor_sysres_used;

    // Target container / main.npdm requirements
    u64 target_tid;
    u32 target_sysres_required;
    u32 target_main_stack_size;
    u8  target_npdm_flags;
    u8  target_main_prio;
    u8  target_main_core;
    bool target_npdm_valid;
    char target_proc_name[17];

    // Derived ABI / environment flags (strictly capability- and ABI-driven, never game-specific)
    bool target_is_switch1;     // Switch 1 ABI class (01... ProgramId)
    bool donor_is_switch1;      // Switch 1 donor process (01... ProgramId)
    bool is_64bit;
    bool vam_capable;           // donor_sysres_total > 0
    bool sysres_sufficient;     // !target_npdm_valid || donor_sysres_total >= target_sysres_required
    bool has_compat1;           // nnCompatThin discovered & attached
    bool has_compat2;           // nnCompat discovered & attached
    bool has_modobj20;          // SDK 20+ ModuleObject layout detected
    char entry_kind[16];        // "5arg" / "4arg" / "manual"
} NupRuntimeCapabilities;
