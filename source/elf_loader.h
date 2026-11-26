// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <switch.h>

#include "nup.h"

#define MAX_LOADED_MODULES 12

typedef struct {
    char name[32];
    bool is_compat;
    u64 nro_base;
    u64 nso_base;
    void* src_buf;
    void* bss_buf;
    u64 rodata_off;
    u64 rodata_size;
    u64 data_mem_off;
    u64 total_size;

    const char* strtab;
    u64 strsz;
    const void* symtab;
    u32 sym_count;
    const void* rela;
    u64 relasz;
    const u64* relr;
    u64 relrsz;
    const void* jmprel;
    u64 pltrelsz;
    u64 init_fn;
    u64 fini_fn;
    const u64* init_array;
    u64 init_arraysz;
    u64 mod0_off;
    u64 dynamic_off;
    u64 module_object_off;
    u64 sysv_hash_off;
    u64 gnu_hash_off;
    u64 pltgot_off;
    u64 relacount;
} LoadedModule;

typedef struct {
    LoadedModule mods[MAX_LOADED_MODULES];
    u32 count;
    bool has_compat;
} ModuleSet;

typedef struct {
    u32 module_count;
    u32 unresolved_count;
    u32 hooked_count;
    u32 unhooked_fs_aoc;
    u32 unhooked_sys;
    u32 total_jmprel;
    u32 total_glob_dat;
    u32 total_tlsdesc;
    u32 trace_selected;
    u32 trace_need_tramp;
    bool has_compat;
    bool has_modobj20;
    char entry_kind[16];
} ElfAuditSummary;

typedef u64 (*SymbolHookFn)(const char* name, u64 real_addr);

Result elfLoadNupModules(ModuleSet* set, NupArchive* nup,
                         const NupFileInfo* exefs, u32 exefs_count);
Result elfLoadNupModulesForAudit(ModuleSet* set, NupArchive* nup,
                                 const NupFileInfo* exefs, u32 exefs_count);
void elfUnloadAuditModules(ModuleSet* set);
bool elfAttachSwitch1Compat(ModuleSet* set, u64 target_tid);
void elfInitSwitch1CompatParams(const ModuleSet* set);
void elfRunCompatInitArrays(ModuleSet* set);
Result elfRelocateAll(ModuleSet* set, SymbolHookFn hook_fn, u32* out_unresolved);
void elfRunStaticAudit(const ModuleSet* set, SymbolHookFn hook_fn,
                       ElfAuditSummary* out_summary);
u64 elfFindSymbol(const ModuleSet* set, const char* name);
u64 elfFindSymbolSkipCompat1(const ModuleSet* set, const char* name);
u64 elfFindSymbolAfterAddr(const ModuleSet* set, u64 caller_addr, const char* name,
                           const char** out_caller_mod, const char** out_found_mod);
const char* elfAddrToSymbol(const ModuleSet* set, u64 addr, u64* out_off);
void elfLogMatchingSymbols(const ModuleSet* set, const char* substr);
void elfRunInitArrays(const ModuleSet* set, void (*after_sdk_cb)(void));
