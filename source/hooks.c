// SPDX-License-Identifier: MIT
// Thin diagnostic & startup compatibility wrappers.
// All FS, AOC/DLC, SM, ldr:ro, Heap, QueryMemoryInfo, and VAM interception is
// handled natively at the SVC/HIPC boundary in svc_entry.s + svc_hipc.c + vfs_romfs.c
// so 100% of Nintendo's SDK C++ code executes unmodified across all SDK versions.
#include "hooks.h"
#include "diag.h"
#include "elf_loader.h"
#include "log.h"
#include "svc_hipc.h"
#include "trace.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

extern ModuleSet g_mods;
volatile u32 g_open_file_count = 0;

static NupRuntimeCapabilities g_caps = {};

// --- Diagnostics & Trace-Mode NVN proxy (zero overhead on Normal Launch) ---

static void (*real_init_libc1)(void) = NULL;
static void (*real_init_sdk_mod)(void) = NULL;
static void (*real_nninitStartup)(void) = NULL;
static bool (*real_MapAliasStack)(const void*, void**, const void*, size_t) = NULL;
static char** (*real_GetHostArgv)(void) = NULL;
static void* (*real_NvnBootstrapLoader)(const char*) = NULL;
static void (*real_AbortImpl0)(void) = NULL;
static void (*real_AbortImplRes)(const u32*) = NULL;
static void (*real_AbortRes)(const u32*) = NULL;
static void (*real_VAbortImpl)(const char*, const char*, const char*, int,
                               const u32*, const void*, const char*, void*) = NULL;
static void (*real_StdAbort)(void) = NULL;
static void (*real_StdTerminate)(void) = NULL;
static void (*real_AssertFail)(const char*, const char*, int, const char*) = NULL;
static void (*real_LibcppVerboseAbort)(const char*, ...) = NULL;
static void (*real_ThrowSystemError)(int, const char*) = NULL;

static void* (*real_NvnDeviceGetProcAddress)(void*, const char*) = NULL;
static u8 (*real_nvnDeviceInitialize)(void*, const void*) = NULL;
static u8 (*real_nvnQueueInitialize)(void*, const void*) = NULL;
static u8 (*real_nvnWindowInitialize)(void*, const void*) = NULL;
static u8 (*real_nvnMemoryPoolInitialize)(void*, const void*) = NULL;
static void (*real_nvnQueuePresentTexture)(void*, void*, int) = NULL;
static void (*real_nvnQueueSubmitCommands)(void*, int, const u64*) = NULL;
static int (*real_nvnQueueGetError)(void*, void*) = NULL;
static u8 (*real_nvnProgramSetShaders)(void*, int, const void*) = NULL;
static u8 (*real_nvnProgramSetShadersExt)(void*, int, const void*) = NULL;

static u32 g_nvn_gpa_logs = 0;
static u32 g_nvn_mempool_calls = 0;
static u32 g_nvn_present_frames = 0;
static u32 g_nvn_submit_calls = 0;
static u32 g_nvn_shader_ok = 0;
static u32 g_nvn_shader_fail = 0;
static volatile u32 g_nvn_err_logged = 0;
static volatile u32 g_nvn_shader_ver_warned = 0;

void hooksInit(NupArchive* nup, FsFileSystem* sd,
               const NupRuntimeCapabilities* caps, Handle hen_sm_proxy) {
    if (caps) g_caps = *caps;
    else memset(&g_caps, 0, sizeof(g_caps));
    g_open_file_count = 0;
    g_nvn_gpa_logs = 0;
    g_nvn_mempool_calls = 0;
    g_nvn_present_frames = 0;
    g_nvn_submit_calls = 0;
    g_nvn_shader_ok = 0;
    g_nvn_shader_fail = 0;
    g_nvn_err_logged = 0;
    g_nvn_shader_ver_warned = 0;
    nupSvcHipcInit(nup, sd, caps, hen_sm_proxy);
}

void hooksSetNvHandle(Handle nv_session) {
    nupSvcHipcSetNvHandle(nv_session);
}

void hooksMarkCompatHeapEnd(void) {
    nupSvcHipcMarkCompatHeapEnd();
}

static void log_used_mem(const char* tag) {
    u64 used = 0, sys_used = 0, sys_tot = 0;
    svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&sys_used, InfoType_SystemResourceSizeUsed, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&sys_tot, InfoType_SystemResourceSizeTotal, CUR_PROCESS_HANDLE, 0);
    nupLogf("[mem] %s: used=0x%llx sysres=0x%llx/0x%llx\n",
            tag, (unsigned long long)used,
            (unsigned long long)sys_used, (unsigned long long)sys_tot);
}

static void hook_init_libc1(void) {
    nupLogf("[6/6] entering _init_libc1 @ %p\n", (void*)real_init_libc1);
    if (real_init_libc1) real_init_libc1();
    nupLogf("[6/6] _init_libc1 returned\n");
}

static void hook_init_sdk_mod(void) {
    nupOnBeforeInitSdkModule();
    elfInitSwitch1CompatParams(&g_mods);
    elfRunCompatInitArrays(&g_mods);
    hooksMarkCompatHeapEnd();
    nupLogf("[6/6] entering nninitInitializeSdkModule @ %p\n", (void*)real_init_sdk_mod);
    if (real_init_sdk_mod) real_init_sdk_mod();
    nupLogf("[6/6] nninitInitializeSdkModule returned\n");
    log_used_mem("after nninitInitializeSdkModule");
}

static bool hook_MapAliasStack(const void* self, void** out_stack, const void* stack, size_t stack_sz) {
    const bool ok = real_MapAliasStack ? real_MapAliasStack(self, out_stack, stack, stack_sz) : false;
    if (!ok) {
        u64 sr_addr = 0, sr_sz = 0;
        svcGetInfo(&sr_addr, InfoType_StackRegionAddress, CUR_PROCESS_HANDLE, 0);
        svcGetInfo(&sr_sz, InfoType_StackRegionSize, CUR_PROCESS_HANDLE, 0);
        u64 cur = sr_addr;
        const u64 end = sr_addr + sr_sz;
        for (int i = 0; i < 64 && cur < end; i++) {
            MemoryInfo mi = {};
            u32 pi = 0;
            if (R_FAILED(svcQueryMemory(&mi, &pi, cur)) || !mi.size)
                break;
            u64 lo = mi.addr < sr_addr ? sr_addr : mi.addr;
            u64 hi = (mi.addr + mi.size) > end ? end : (mi.addr + mi.size);
            if (mi.type == MemType_Unmapped && hi > lo && (hi - lo) >= stack_sz + 0x20000) {
                const u64 probe_dst = (lo + 0x10000ULL + 0xffffULL) & ~0xffffULL;
                if (probe_dst >= sr_addr && probe_dst + stack_sz <= end &&
                    R_SUCCEEDED(svcMapMemory((void*)(uintptr_t)probe_dst, (void*)(uintptr_t)stack, stack_sz))) {
                    if (out_stack) *out_stack = (void*)(uintptr_t)probe_dst;
                    nupLogf("[os] recovered MapAliasStack dst=0x%llx sz=0x%zx\n",
                            (unsigned long long)probe_dst, stack_sz);
                    return true;
                }
            }
            cur = mi.addr + mi.size;
        }
    }
    return ok;
}

static char g_safe_argv0[] = "";
static char* g_safe_argv[] = { g_safe_argv0, NULL };

static char** hook_GetHostArgv(void) {
    char** argv = real_GetHostArgv ? real_GetHostArgv() : NULL;
    if (argv) {
        MemoryInfo mi = {};
        u32 pi = 0;
        if (R_SUCCEEDED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)argv)) && (mi.perm & Perm_R)) {
            char* p0 = argv[0];
            if (p0 && R_SUCCEEDED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)p0)) && (mi.perm & Perm_R))
                return argv;
        }
    }
    return g_safe_argv;
}

static void hook_GetProcessNamePointer(const char** out_name, u64* out_len) {
    static const char fallback[] = "Application";
    const char* name = (g_caps.target_npdm_valid && g_caps.target_proc_name[0])
                           ? g_caps.target_proc_name : fallback;
    if (out_name) *out_name = name;
    if (out_len) *out_len = strlen(name);
}

static void hook_nninitStartup(void) {
    nupOnBeforeNninitStartup();
    nupLogf("[6/6] entering nninitStartup @ %p\n", (void*)real_nninitStartup);
    nupSvcHipcSetInStartup(true);
    if (real_nninitStartup) real_nninitStartup();
    nupSvcHipcSetInStartup(false);
    nupLogf("[6/6] nninitStartup returned!\n");
    log_used_mem("after nninitStartup");
}

static void log_gpu_remote_inline(u64* out_used, u64* out_tot) {
    u64 u = 0, t = 0;
    if (R_SUCCEEDED(svcGetInfo(&t, 31, CUR_PROCESS_HANDLE, 0)))
        svcGetInfo(&u, 32, CUR_PROCESS_HANDLE, 0);
    if (out_used) *out_used = u;
    if (out_tot) *out_tot = t;
}

static bool hooks_is_readable(u64 addr, u64 sz) {
    if (!addr || addr < 0x10000ull) return false;
    MemoryInfo mi = {};
    u32 pi = 0;
    if (R_FAILED(svcQueryMemory(&mi, &pi, addr))) return false;
    return (mi.perm & Perm_R) && (addr + sz <= mi.addr + mi.size);
}

static void check_compat2_shader_version(int count, const void* stageData) {
    if (!g_caps.has_compat2 || !stageData || count <= 0)
        return;
    if (__atomic_load_n(&g_nvn_shader_ver_warned, __ATOMIC_RELAXED))
        return;
    if (!hooks_is_readable((u64)(uintptr_t)stageData, 16))
        return;
    const u64 ctrl = *(const u64*)((const u8*)stageData + 8);
    if (!ctrl || !hooks_is_readable(ctrl, 12))
        return;
    const u32 magic = *(const u32*)(uintptr_t)(ctrl + 0);
    const u32 ver   = *(const u32*)(uintptr_t)(ctrl + 4);
    const u32 sub   = *(const u32*)(uintptr_t)(ctrl + 8);
    if (magic == 0x98761234u && ver != 1u) {
        if (__atomic_exchange_n(&g_nvn_shader_ver_warned, 1u, __ATOMIC_RELAXED) == 0u) {
            nupLogf("!!! [nvn] COMPAT2 SHADER VERSION MISMATCH: magic=0x%08x ver=%u subver=%u "
                    "(compat2 requires ver=1 Maxwell; ver=201 is Switch 2 Ampere - check RomFS / launch program1)\n",
                    magic, ver, sub);
            nupLogFlush();
        }
    }
}

static u8 wrap_nvnDeviceInitialize(void* dev, const void* builder) {
    u64 gu = 0, gt = 0;
    log_gpu_remote_inline(&gu, &gt);
    const u8 ok = real_nvnDeviceInitialize ? real_nvnDeviceInitialize(dev, builder) : 0;
    log_gpu_remote_inline(&gu, &gt);
    nupLogf("[nvn] nvnDeviceInitialize(dev=%p) -> %u (gpu=%llu/%llu MiB)\n",
            dev, (unsigned)ok, (unsigned long long)(gu >> 20), (unsigned long long)(gt >> 20));
    return ok;
}

static u8 wrap_nvnQueueInitialize(void* q, const void* builder) {
    const u8 ok = real_nvnQueueInitialize ? real_nvnQueueInitialize(q, builder) : 0;
    u64 gu = 0, gt = 0;
    log_gpu_remote_inline(&gu, &gt);
    nupLogf("[nvn] nvnQueueInitialize(q=%p) -> %u (gpu=%llu/%llu MiB)\n",
            q, (unsigned)ok, (unsigned long long)(gu >> 20), (unsigned long long)(gt >> 20));
    return ok;
}

static u8 wrap_nvnWindowInitialize(void* w, const void* builder) {
    const u8 ok = real_nvnWindowInitialize ? real_nvnWindowInitialize(w, builder) : 0;
    nupLogf("[nvn] nvnWindowInitialize(w=%p) -> %u\n", w, (unsigned)ok);
    return ok;
}

static u8 wrap_nvnMemoryPoolInitialize(void* pool, const void* builder) {
    const u8 ok = real_nvnMemoryPoolInitialize ? real_nvnMemoryPoolInitialize(pool, builder) : 0;
    const u32 n = __atomic_add_fetch(&g_nvn_mempool_calls, 1u, __ATOMIC_RELAXED);
    if (!ok || n <= 16 || (n & (n - 1u)) == 0u) {
        u64 gu = 0, gt = 0;
        log_gpu_remote_inline(&gu, &gt);
        nupLogf("[nvn] nvnMemoryPoolInitialize #%u -> %u%s (gpu=%llu/%llu MiB)\n",
                n, (unsigned)ok, ok ? "" : " [FAILED]",
                (unsigned long long)(gu >> 20), (unsigned long long)(gt >> 20));
    }
    return ok;
}

static u8 wrap_nvnProgramSetShaders(void* prog, int count, const void* stageData) {
    check_compat2_shader_version(count, stageData);
    const u8 ok = real_nvnProgramSetShaders ? real_nvnProgramSetShaders(prog, count, stageData) : 0;
    if (ok) __atomic_add_fetch(&g_nvn_shader_ok, 1u, __ATOMIC_RELAXED);
    else __atomic_add_fetch(&g_nvn_shader_fail, 1u, __ATOMIC_RELAXED);
    return ok;
}

static u8 wrap_nvnProgramSetShadersExt(void* prog, int count, const void* stageData) {
    check_compat2_shader_version(count, stageData);
    const u8 ok = real_nvnProgramSetShadersExt ? real_nvnProgramSetShadersExt(prog, count, stageData) : 0;
    if (ok) __atomic_add_fetch(&g_nvn_shader_ok, 1u, __ATOMIC_RELAXED);
    else __atomic_add_fetch(&g_nvn_shader_fail, 1u, __ATOMIC_RELAXED);
    return ok;
}

static void wrap_nvnQueueSubmitCommands(void* q, int numCommands, const u64* handles) {
    const u32 s = __atomic_add_fetch(&g_nvn_submit_calls, 1u, __ATOMIC_RELAXED);
    if (real_nvnQueueSubmitCommands) real_nvnQueueSubmitCommands(q, numCommands, handles);
    if (s == 1 && !g_nvn_err_logged && real_nvnQueueGetError) {
        u64 info[8] = {};
        const int err = real_nvnQueueGetError(q, info);
        if (err != 0) {
            g_nvn_err_logged = 1;
            nupLogf("!!! [nvn] nvnQueueGetError after submit #1 -> err=%d (shaders=%u/%u pools=%u)\n",
                    err, g_nvn_shader_ok, g_nvn_shader_fail, g_nvn_mempool_calls);
            nupLogFlush();
        }
    }
}

static void wrap_nvnQueuePresentTexture(void* q, void* w, int idx) {
    const u32 f = __atomic_add_fetch(&g_nvn_present_frames, 1u, __ATOMIC_RELAXED);
    if (f <= 3 || f == 10 || f == 60 || (f % 300u) == 0u) {
        u64 gu = 0, gt = 0;
        log_gpu_remote_inline(&gu, &gt);
        nupLogf("[nvn] Present frame #%u (submits=%u shaders=%u/%u gpu=%llu/%llu MiB)\n",
                f, g_nvn_submit_calls, g_nvn_shader_ok, g_nvn_shader_fail,
                (unsigned long long)(gu >> 20), (unsigned long long)(gt >> 20));
    }
    if (real_nvnQueuePresentTexture) real_nvnQueuePresentTexture(q, w, idx);
}

static void* hook_NvnDeviceGetProcAddress(void* dev, const char* name) {
    void* fn = real_NvnDeviceGetProcAddress ? real_NvnDeviceGetProcAddress(dev, name) : NULL;
    if (nupTraceIsEnabled() && name && name[0] && fn) {
        if (g_nvn_gpa_logs < 64) {
            g_nvn_gpa_logs++;
            nupLogBufferedf("  [nvn_gpa #%u] '%s' -> %p\n", g_nvn_gpa_logs, name, fn);
        }
        if (strcmp(name, "nvnDeviceInitialize") == 0) { real_nvnDeviceInitialize = (u8 (*)(void*, const void*))fn; return (void*)wrap_nvnDeviceInitialize; }
        if (strcmp(name, "nvnQueueInitialize") == 0) { real_nvnQueueInitialize = (u8 (*)(void*, const void*))fn; return (void*)wrap_nvnQueueInitialize; }
        if (strcmp(name, "nvnWindowInitialize") == 0) { real_nvnWindowInitialize = (u8 (*)(void*, const void*))fn; return (void*)wrap_nvnWindowInitialize; }
        if (strcmp(name, "nvnMemoryPoolInitialize") == 0) { real_nvnMemoryPoolInitialize = (u8 (*)(void*, const void*))fn; return (void*)wrap_nvnMemoryPoolInitialize; }
        if (strcmp(name, "nvnQueuePresentTexture") == 0) { real_nvnQueuePresentTexture = (void (*)(void*, void*, int))fn; return (void*)wrap_nvnQueuePresentTexture; }
        if (strcmp(name, "nvnQueueSubmitCommands") == 0) { real_nvnQueueSubmitCommands = (void (*)(void*, int, const u64*))fn; return (void*)wrap_nvnQueueSubmitCommands; }
        if (strcmp(name, "nvnQueueGetError") == 0) { real_nvnQueueGetError = (int (*)(void*, void*))fn; }
        if (strcmp(name, "nvnProgramSetShaders") == 0) { real_nvnProgramSetShaders = (u8 (*)(void*, int, const void*))fn; return (void*)wrap_nvnProgramSetShaders; }
        if (strcmp(name, "nvnProgramSetShadersExt") == 0) { real_nvnProgramSetShadersExt = (u8 (*)(void*, int, const void*))fn; return (void*)wrap_nvnProgramSetShadersExt; }
        const u64 tramp = nupTraceWrapDynamicProc("nvn_gpa", name, (u64)(uintptr_t)fn);
        if (tramp) return (void*)(uintptr_t)tramp;
    }
    return fn;
}

static void* hook_NvnBootstrapLoader(const char* name) {
    void* p = real_NvnBootstrapLoader ? real_NvnBootstrapLoader(name) : NULL;
    if (nupTraceIsEnabled() && name && strcmp(name, "nvnDeviceGetProcAddress") == 0 && p) {
        real_NvnDeviceGetProcAddress = (void* (*)(void*, const char*))p;
        return (void*)hook_NvnDeviceGetProcAddress;
    }
    return p;
}

// --- Abort / crash diagnostics ---

static const char* safe_cstr(const char* p) {
    if (!p || (u64)(uintptr_t)p < 0x10000ull)
        return "<null>";
    MemoryInfo mi = {};
    u32 pi = 0;
    if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)p)) || !(mi.perm & Perm_R))
        return "<unreadable>";
    return p[0] ? p : "\"\"";
}

static void hook_AbortImpl0(void) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogBacktrace("nn::diag::detail::AbortImpl()", caller, 0, 0);
    if (real_AbortImpl0) real_AbortImpl0();
}

static void hook_AbortImplRes(const u32* res) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    u32 val = (res && hooks_is_readable((u64)(uintptr_t)res, 4)) ? *res : 0;
    nupLogf("!!! AbortImpl(Result): val=0x%x (mod=%u desc=%u)\n", val, R_MODULE(val), R_DESCRIPTION(val));
    nupLogBacktrace("nn::diag::detail::AbortImpl(Result)", caller, val, (u64)(uintptr_t)res);
    if (real_AbortImplRes) real_AbortImplRes(res);
}

static void hook_AbortRes(const u32* res) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    u32 val = (res && hooks_is_readable((u64)(uintptr_t)res, 4)) ? *res : 0;
    nupLogf("!!! Abort(Result): val=0x%x (mod=%u desc=%u)\n", val, R_MODULE(val), R_DESCRIPTION(val));
    nupLogBacktrace("nn::diag::detail::Abort(Result)", caller, val, (u64)(uintptr_t)res);
    if (real_AbortRes) real_AbortRes(res);
}

static void hook_VAbortImpl(const char* expr, const char* func, const char* file, int line,
                            const u32* res, const void* exc, const char* fmt, void* ap_ptr) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    u64 tid = 0;
    svcGetThreadId(&tid, CUR_THREAD_HANDLE);
    u32 rval = 0;
    bool has_res = false;
    if (res && hooks_is_readable((u64)(uintptr_t)res, 4)) {
        rval = *res;
        has_res = true;
    }
    nupLogf("!!! VAbortImpl tid=%llu expr='%.80s' func='%.80s' file='%.80s':%d res=%s(0x%x mod=%u desc=%u) exc=%p fmt='%.80s'\n",
            (unsigned long long)tid, safe_cstr(expr), safe_cstr(func), safe_cstr(file), line,
            has_res ? "YES" : "NO", rval, R_MODULE(rval), R_DESCRIPTION(rval), exc, safe_cstr(fmt));
    if (fmt && hooks_is_readable((u64)(uintptr_t)fmt, 1) && ap_ptr && hooks_is_readable((u64)(uintptr_t)ap_ptr, sizeof(va_list)) && fmt[0]) {
        char msg[256];
        va_list ap_copy;
        va_copy(ap_copy, *(va_list*)ap_ptr);
        _vsnprintf_r(_impure_ptr, msg, sizeof(msg), fmt, ap_copy);
        va_end(ap_copy);
        nupLogf("!!! VAbortImpl msg: '%.240s'\n", msg);
    }
    nupLogBacktrace("nn::diag::detail::VAbortImpl", caller, rval, (u64)line);
    if (real_VAbortImpl) real_VAbortImpl(expr, func, file, line, res, exc, fmt, ap_ptr);
}

static void hook_StdAbort(void) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupDiagDumpAbortContext(caller);
    nupLogBacktrace("abort()", caller, 0, 0);
    if (real_StdAbort) real_StdAbort();
}

static void hook_StdTerminate(void) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogBacktrace("std::terminate()", caller, 0, 0);
    if (real_StdTerminate) real_StdTerminate();
}

static void hook_AssertFail(const char* expr, const char* file, int line, const char* func) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogf("!!! __assert_fail: expr='%s' file='%s':%d func='%s'\n",
            expr ? expr : "?", file ? file : "?", line, func ? func : "?");
    nupLogBacktrace("__assert_fail", caller, (u64)line, 0);
    if (real_AssertFail) real_AssertFail(expr, file, line, func);
}

static void hook_LibcppVerboseAbort(const char* fmt, ...) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogf("!!! __libcpp_verbose_abort: fmt='%s'\n", fmt ? fmt : "?");
    nupLogBacktrace("__libcpp_verbose_abort", caller, 0, 0);
    if (real_LibcppVerboseAbort) real_LibcppVerboseAbort(fmt);
}

static void hook_ThrowSystemError(int ev, const char* what) {
    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    nupLogf("!!! __throw_system_error: ev=%d what='%s'\n", ev, what ? what : "?");
    nupLogBacktrace("__throw_system_error", caller, (u64)ev, 0);
    if (real_ThrowSystemError) real_ThrowSystemError(ev, what);
}

// --- Minimal Diagnostic Registry (zero HLE for FS / AOC / SM / OS / RO) ---

typedef struct {
    const char* sym_name;
    void* hook_fn;
    void** real_slot;
    HookProviderKind provider;
    bool terminal_for_compat;
} HookProviderEntry;

#define PROV_WRAP(sym, fn, real, prov, term) { (sym), (void*)(fn), (void**)&(real), (prov), (term) }

static const HookProviderEntry g_hook_registry[] = {
    PROV_WRAP("_init_libc1", hook_init_libc1, real_init_libc1, HOOK_PROV_SVC, false),
    PROV_WRAP("nninitInitializeSdkModule", hook_init_sdk_mod, real_init_sdk_mod, HOOK_PROV_SVC, false),
    PROV_WRAP("nninitStartup", hook_nninitStartup, real_nninitStartup, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZNK2nn2os6detail26ThreadManagerImplByHorizon13MapAliasStackEPPvPKvm", hook_MapAliasStack, real_MapAliasStack, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn2os11GetHostArgvEv", hook_GetHostArgv, real_GetHostArgv, HOOK_PROV_SVC, false),
    { "_ZN2nn4diag6detail21GetProcessNamePointerEPPKcPm", (void*)hook_GetProcessNamePointer, NULL, HOOK_PROV_SVC, true },
    // NOTE: Never hook nnMain — sdk's __nnmusl_init_dso checks GOT[nnMain] against
    // [text_start, text_end) to recognize the main DSO and initialize ELF PT_TLS.
    PROV_WRAP("nvnBootstrapLoader", hook_NvnBootstrapLoader, real_NvnBootstrapLoader, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn4diag6detail9AbortImplEv", hook_AbortImpl0, real_AbortImpl0, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn4diag6detail9AbortImplEPKNS_6ResultE", hook_AbortImplRes, real_AbortImplRes, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn4diag6detail5AbortEPKNS_6ResultE", hook_AbortRes, real_AbortRes, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZN2nn4diag6detail10VAbortImplEPKcS3_S3_iPKNS_6ResultEPKNS_2os17UserExceptionInfoES3_RSt9__va_list", hook_VAbortImpl, real_VAbortImpl, HOOK_PROV_SVC, false),
    PROV_WRAP("abort", hook_StdAbort, real_StdAbort, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZSt9terminatev", hook_StdTerminate, real_StdTerminate, HOOK_PROV_SVC, false),
    PROV_WRAP("__assert_fail", hook_AssertFail, real_AssertFail, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZNSt3__122__libcpp_verbose_abortEPKcz", hook_LibcppVerboseAbort, real_LibcppVerboseAbort, HOOK_PROV_SVC, false),
    PROV_WRAP("_ZNSt3__120__throw_system_errorEiPKc", hook_ThrowSystemError, real_ThrowSystemError, HOOK_PROV_SVC, false),
};

static const HookProviderEntry* find_registry_entry(const char* sym_name) {
    if (!sym_name || !sym_name[0])
        return NULL;
    const size_t n = sizeof(g_hook_registry) / sizeof(g_hook_registry[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(sym_name, g_hook_registry[i].sym_name) == 0)
            return &g_hook_registry[i];
    }
    return NULL;
}

const char* hooksProviderName(HookProviderKind kind) {
    switch (kind) {
    case HOOK_PROV_FS:    return "FS";
    case HOOK_PROV_AOC:   return "AOC";
    case HOOK_PROV_MEM:   return "MEM";
    case HOOK_PROV_ALLOC: return "ALLOC";
    case HOOK_PROV_RTLD:  return "RTLD";
    case HOOK_PROV_SVC:   return "SVC";
    default:              return "NONE";
    }
}

HookProviderKind hooksQueryProvider(const char* sym_name, bool* out_terminal_for_compat) {
    const HookProviderEntry* e = find_registry_entry(sym_name);
    if (!e) {
        if (out_terminal_for_compat) *out_terminal_for_compat = false;
        return HOOK_PROV_NONE;
    }
    if (out_terminal_for_compat) *out_terminal_for_compat = e->terminal_for_compat;
    return e->provider;
}

u64 hooksResolve(const char* sym_name, u64 real_addr) {
    const HookProviderEntry* e = find_registry_entry(sym_name);
    if (!e)
        return 0;
    if (real_addr && e->real_slot)
        *e->real_slot = (void*)(uintptr_t)real_addr;
    return (u64)(uintptr_t)e->hook_fn;
}

u32 hooksLookupNextForCompat(uintptr_t* out_addr, const char* sym_name) {
    if (!out_addr || !sym_name || !sym_name[0])
        return MAKERESULT(22, 5); // 0xa16 (nn::ro SymbolNotFound)

    const u64 caller = (u64)(uintptr_t)__builtin_return_address(0);
    const char* caller_mod = "?";
    const char* found_mod = "?";
    u64 addr = elfFindSymbolAfterAddr(&g_mods, caller, sym_name, &caller_mod, &found_mod);
    if (!addr) {
        char caller_s[64];
        nupFmtAddrMod(caller, caller_s, sizeof(caller_s));
        nupLogf("[compat] LookupNextSymbolForCompat('%s' from %s @ %s) -> NOT FOUND\n",
                sym_name, caller_mod, caller_s);
        *out_addr = 0;
        return MAKERESULT(22, 5);
    }
    if (nupTraceIsEnabled()) {
        nupLogBufferedf("[compat_next] '%s' (%s -> %s) -> 0x%llx\n",
                        sym_name, caller_mod, found_mod, (unsigned long long)addr);
        const u64 tramp = nupTraceWrapPlt("compat_next", sym_name, addr);
        if (tramp)
            addr = tramp;
    }
    *out_addr = (uintptr_t)addr;
    return 0;
}
