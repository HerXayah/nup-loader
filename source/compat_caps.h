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
    u64 donor_remote_total;
    u64 donor_remote_used;
    bool donor_remote_valid;

    // Target container / effective main.npdm declarations (advisory ceilings, not hard minimums)
    u64 target_tid;
    u32 target_remote_required;
    u32 target_sysres_required;
    u32 target_main_stack_size;
    u32 target_sac_count;
    u8  target_npdm_flags;
    u8  target_main_prio;
    u8  target_main_core;
    bool target_npdm_valid;
    bool target_sac_valid;
    bool target_declares_legacy_stack;
    bool target_declares_sw2_stack;
    char target_proc_name[17];
    char target_stack_services[96];

    // Derived ABI / capability negotiation flags (strictly capability- and ABI-driven)
    bool target_is_switch1;     // Switch 1 / legacy stack ABI class
    bool donor_is_switch1;      // Switch 1 / legacy donor host process
    bool platform_stack_match;  // Donor stack matches target stack
    bool is_64bit;
    bool vam_capable;           // donor_sysres_total > 0 (enables SDK VAM path at runtime)
    bool target_declares_vam;   // target_npdm_valid && target_sysres_required > 0
    bool sysres_covers_declared;// !target_npdm_valid || donor_sysres_total >= target_sysres_required
    bool has_compat1;           // nnCompatThin discovered & attached
    bool has_compat2;           // nnCompat discovered & attached
    bool has_modobj20;          // SDK 20+ ModuleObject layout detected
    char entry_kind[16];        // "5arg" / "4arg" / "manual"
} NupRuntimeCapabilities;
