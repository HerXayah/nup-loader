// SPDX-License-Identifier: MIT
#include "caps.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool str_in_list(const char* s, const char* const* list, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(s, list[i]) == 0)
            return true;
    }
    return false;
}

static void append_stack_svc(NupRuntimeCapabilities* caps, const char* svc) {
    const size_t cur = strlen(caps->target_stack_services);
    const size_t add = strlen(svc);
    if (cur + add + 2 >= sizeof(caps->target_stack_services))
        return;
    if (cur > 0) {
        caps->target_stack_services[cur] = ',';
        memcpy(caps->target_stack_services + cur + 1, svc, add + 1);
    } else {
        memcpy(caps->target_stack_services, svc, add + 1);
    }
}

void nupCollectRuntimeCaps(NupRuntimeCapabilities* caps, NupArchive* nup,
                           const NupFileInfo* exefs, u32 exefs_count,
                           const ModuleSet* mods, u64 target_tid) {
    memset(caps, 0, sizeof(*caps));
    caps->target_tid = target_tid;
    caps->target_is_switch1 = ((target_tid >> 56) == 0x01);

    svcGetInfo(&caps->donor_pid, InfoType_ProgramId, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_mem_used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_mem_total, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_sysres_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&caps->donor_sysres_total, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
    if (R_SUCCEEDED(svcGetInfo(&caps->donor_remote_total, 31, CUR_PROCESS_HANDLE, 0))) {
        caps->donor_remote_valid = true;
        svcGetInfo(&caps->donor_remote_used, 32, CUR_PROCESS_HANDLE, 0);
    }

    caps->donor_is_switch1 = ((caps->donor_pid >> 56) == 0x01);
    caps->vam_capable = (caps->donor_sysres_total > 0);
    caps->sysres_covers_declared = true;

    // Parse effective target main.npdm (META + ACI0 Service Access Control)
    const NupFileInfo* npdm_fi = NULL;
    for (u32 i = 0; i < exefs_count; i++) {
        if (strcmp(exefs[i].name, "main.npdm") == 0) {
            npdm_fi = &exefs[i];
            break;
        }
    }
    if (npdm_fi && npdm_fi->size >= 0x80) {
        const size_t rlen = npdm_fi->size < 0x2000 ? (size_t)npdm_fi->size : 0x2000;
        u8* npdm = (u8*)malloc(rlen);
        if (npdm) {
            memset(npdm, 0, rlen);
            if (R_SUCCEEDED(nupReadExefs(nup, npdm_fi, 0, npdm, rlen)) &&
                memcmp(npdm, "META", 4) == 0) {
                caps->target_npdm_valid = true;
                caps->target_npdm_flags = npdm[0x0c];
                caps->target_main_prio = npdm[0x0e];
                caps->target_main_core = npdm[0x0f];
                memcpy(&caps->target_remote_required, npdm + 0x10, 4);
                memcpy(&caps->target_sysres_required, npdm + 0x14, 4);
                memcpy(&caps->target_main_stack_size, npdm + 0x1c, 4);
                memcpy(caps->target_proc_name, npdm + 0x20, 16);
                caps->target_proc_name[16] = '\0';
                caps->is_64bit = (caps->target_npdm_flags & 1) != 0;
                caps->target_declares_vam = (caps->target_sysres_required > 0);
                caps->sysres_covers_declared = (caps->donor_sysres_total >= (u64)caps->target_sysres_required);

                // Parse ACI0 -> SAC (Service Access Control)
                u32 aci0_off = 0, aci0_sz = 0;
                memcpy(&aci0_off, npdm + 0x70, 4);
                memcpy(&aci0_sz, npdm + 0x74, 4);
                if (aci0_off + 0x38 <= rlen && aci0_sz >= 0x38 &&
                    memcmp(npdm + aci0_off, "ACI0", 4) == 0) {
                    u32 sac_off = 0, sac_sz = 0;
                    memcpy(&sac_off, npdm + aci0_off + 0x28, 4);
                    memcpy(&sac_sz, npdm + aci0_off + 0x2c, 4);
                    const u64 sac_start = (u64)aci0_off + sac_off;
                    const u64 sac_end = sac_start + sac_sz;
                    if (sac_sz > 0 && sac_end <= rlen) {
                        static const char* const k_legacy_svcs[] = {
                            "nvdrv", "vi:u", "audren:u", "audout:u", "audin:u",
                            "pcm", "mm:u", "bsdcfg", "ngct:u"
                        };
                        static const char* const k_sw2_svcs[] = {
                            "aud:u", "auddmg:u", "audsmx:u", "imf",
                            "chat:u", "stpl:u", "mnpp:app"
                        };
                        caps->target_sac_valid = true;
                        u64 pos = sac_start;
                        while (pos < sac_end) {
                            const u8 ctrl = npdm[pos++];
                            const bool is_server = (ctrl & 0x80u) != 0;
                            const u32 nlen = (u32)(ctrl & 0x07u) + 1u;
                            if (pos + nlen > sac_end)
                                break;
                            if (!is_server) {
                                char svc[9] = {};
                                memcpy(svc, npdm + pos, nlen);
                                caps->target_sac_count++;
                                if (str_in_list(svc, k_legacy_svcs, sizeof(k_legacy_svcs) / sizeof(k_legacy_svcs[0]))) {
                                    caps->target_declares_legacy_stack = true;
                                    append_stack_svc(caps, svc);
                                } else if (str_in_list(svc, k_sw2_svcs, sizeof(k_sw2_svcs) / sizeof(k_sw2_svcs[0]))) {
                                    caps->target_declares_sw2_stack = true;
                                    append_stack_svc(caps, svc);
                                }
                            }
                            pos += nlen;
                        }
                    }
                }
            }
            free(npdm);
        }
    }

    caps->platform_stack_match = (caps->donor_is_switch1 == caps->target_is_switch1);

    if (mods) {
        for (u32 m = 0; m < mods->count; m++) {
            const LoadedModule* mod = &mods->mods[m];
            if (strcmp(mod->name, "compat1") == 0) caps->has_compat1 = true;
            if (strcmp(mod->name, "compat2") == 0) caps->has_compat2 = true;
            const u32 fw = mod->nso_base ? *(const u32*)(uintptr_t)mod->nso_base : 0;
            if (fw == 1 && mod->module_object_off) caps->has_modobj20 = true;
        }
        const u64 s5 = elfFindSymbolSkipCompat1(mods, "_ZN2nn4init5StartEmmPFvvES2_S2_");
        const u64 s4 = elfFindSymbolSkipCompat1(mods, "_ZN2nn4init5StartEmmPFvvES2_");
        snprintf(caps->entry_kind, sizeof(caps->entry_kind), "%s",
                 s5 ? "5arg" : (s4 ? "4arg" : "manual"));
    }
}

void nupLogRuntimeCaps(const NupRuntimeCapabilities* c) {
    const u64 donor_free = (c->donor_mem_total > c->donor_mem_used)
                               ? (c->donor_mem_total - c->donor_mem_used) : 0;
    const char* donor_stack = c->donor_is_switch1 ? "LEGACY (0100...)" : "NATIVE_SW2 (0400...)";
    const char* target_stack = c->target_is_switch1 ? "LEGACY (0100...)" : "NATIVE_SW2 (0400...)";
    const char* cpack = (c->has_compat1 && c->has_compat2) ? "ATTACHED (compat1+compat2)"
                      : (!c->target_is_switch1 ? "NOT NEEDED"
                      : "MISSING (Switch 1 ABI target requires legacy 0100 donor)");

    nupLogBufferedf("\n--- HOST / DONOR CAPABILITIES ---\n");
    nupLogBufferedf("  Donor ProgramId:           %016llx\n", (unsigned long long)c->donor_pid);
    nupLogBufferedf("  Platform stack:            %s\n", donor_stack);
    nupLogBufferedf("  Ordinary process memory:   used=0x%llx / total=0x%llx (free=%llu MiB, pre-shrink host heap)\n",
                    (unsigned long long)c->donor_mem_used, (unsigned long long)c->donor_mem_total,
                    (unsigned long long)(donor_free / (1024ULL * 1024ULL)));
    nupLogBufferedf("  System resource capacity:  %llu MiB (0x%llx, used=0x%llx)\n",
                    (unsigned long long)(c->donor_sysres_total / (1024ULL * 1024ULL)),
                    (unsigned long long)c->donor_sysres_total,
                    (unsigned long long)c->donor_sysres_used);
    if (c->donor_remote_valid) {
        nupLogBufferedf("  GPU remote memory:         %llu MiB (0x%llx, used=%llu MiB)\n",
                        (unsigned long long)(c->donor_remote_total / (1024ULL * 1024ULL)),
                        (unsigned long long)c->donor_remote_total,
                        (unsigned long long)(c->donor_remote_used / (1024ULL * 1024ULL)));
    }
    nupLogBufferedf("  VAM enabled:               %s\n", c->vam_capable ? "YES" : "NO");
    nupLogBufferedf("  CompatibilityPack:         %s\n", cpack);

    nupLogBufferedf("\n--- TARGET DECLARATIONS (effective main.npdm) ---\n");
    nupLogBufferedf("  Target ProgramId:          %016llx\n", (unsigned long long)c->target_tid);
    nupLogBufferedf("  Platform stack:            %s\n", target_stack);
    if (c->target_npdm_valid) {
        nupLogBufferedf("  Target main.npdm:          name='%s' flags=0x%02x (64bit=%d, addrspace=%u) prio=%u core=%u stack=0x%x\n",
                        c->target_proc_name, c->target_npdm_flags, c->is_64bit ? 1 : 0,
                        (c->target_npdm_flags >> 1) & 7, c->target_main_prio, c->target_main_core,
                        c->target_main_stack_size);
        nupLogBufferedf("  Declared system resource:  %u MiB (0x%x)\n",
                        c->target_sysres_required / (1024u * 1024u), c->target_sysres_required);
        nupLogBufferedf("  Declared GPU remote mem:   %u MiB (0x%x)\n",
                        c->target_remote_required / (1024u * 1024u), c->target_remote_required);
        if (c->target_sac_valid) {
            nupLogBufferedf("  Declared services (SAC):   %u client services (stack markers: %s)\n",
                            c->target_sac_count,
                            c->target_stack_services[0] ? c->target_stack_services : "none");
        }
    } else {
        nupLogBufferedf("  Target main.npdm:          NOT FOUND / UNREADABLE\n");
    }

    nupLogBufferedf("\n--- COMPATIBILITY NEGOTIATION ---\n");
    nupLogBufferedf("  Platform stack:            %s\n",
                    c->platform_stack_match ? "MATCH"
                    : "MISMATCH [HARD BLOCKER: pair 0100 with 0100 donor, 0400 with 0400 donor]");
    if (c->target_declares_vam && !c->vam_capable) {
        nupLogBufferedf("  VAM availability:          BLOCKER (donor sysres=0; flat fallback active)\n");
    } else if (!c->target_declares_vam && c->vam_capable) {
        nupLogBufferedf("  VAM availability:          PASS (note: nonzero donor enables SDK VAM path)\n");
    } else {
        nupLogBufferedf("  VAM availability:          %s\n", c->vam_capable ? "PASS" : "OFF");
    }
    nupLogBufferedf("  System resource:           RUNTIME-BOUNDED (donor=%llu MiB vs declared=%u MiB)\n",
                    (unsigned long long)(c->donor_sysres_total / (1024ULL * 1024ULL)),
                    c->target_sysres_required / (1024u * 1024u));
    nupLogBufferedf("  Ordinary process memory:   RUNTIME-BOUNDED (pre-shrink free=%llu MiB; host heap reclaimed at handoff)\n",
                    (unsigned long long)(donor_free / (1024ULL * 1024ULL)));
    if (c->donor_remote_valid) {
        const bool less = c->target_npdm_valid && c->donor_remote_total < (u64)c->target_remote_required;
        nupLogBufferedf("  GPU remote memory:         RUNTIME-BOUNDED (donor=%llu MiB, used=%llu MiB vs declared=%u MiB)%s\n",
                        (unsigned long long)(c->donor_remote_total / (1024ULL * 1024ULL)),
                        (unsigned long long)(c->donor_remote_used / (1024ULL * 1024ULL)),
                        c->target_remote_required / (1024u * 1024u),
                        less ? " [DONOR LOWER THAN DECLARED]" : "");
    } else {
        nupLogBufferedf("  GPU remote memory:         RUNTIME-BOUNDED (donor-inherited ceiling)\n");
    }
    nupLogBufferedf("  Service ACL:               DONOR-INHERITED + HEN SM proxy fallback (0x1015 logged)\n");
}
