// SPDX-License-Identifier: MIT
#include "log.h"
#include "nup.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/reent.h>

typedef struct {
    u32 magic;
    Handle handle;
    Thread* thread_ptr;
    struct _reent* reent;
    void* tls_tp;
} NupThreadVars;

#define NUP_THREADVARS_MAGIC 0x21545624u

volatile u64 g_bad_reent_callers[8] = {};
volatile u32 g_bad_reent_count = 0;

static struct _reent* safe_getreent(u64 caller) {
    NupThreadVars* tv = (NupThreadVars*)((u8*)armGetTls() + 0x1E0);
    if (tv && tv->magic == NUP_THREADVARS_MAGIC && tv->reent)
        return tv->reent;
    u32 idx = __atomic_fetch_add(&g_bad_reent_count, 1, __ATOMIC_RELAXED);
    if (idx < 8)
        g_bad_reent_callers[idx] = caller;
    return _impure_ptr;
}

struct _reent* __wrap___getreent(void) {
    return safe_getreent((u64)(uintptr_t)__builtin_return_address(0));
}

struct _reent* __wrap___syscall_getreent(void) {
    return safe_getreent((u64)(uintptr_t)__builtin_return_address(0));
}

#define LOG_RING_SIZE 65536u

static FsFileSystem* g_log_sd = NULL;
static char g_log_path[FS_MAX_PATH] = {};
static FsFile g_log_file = {};
static bool g_log_open = false;
static bool g_log_handle_open = false;
static bool g_log_persistent = false;
static s64 g_log_pos = 0;
static NupSpinLock g_log_lock;

static char g_ring[LOG_RING_SIZE];
static u32 g_ring_head = 0;
static u32 g_ring_count = 0;

static bool log_write_raw_locked(const char* data, size_t len) {
    if (!g_log_open || !g_log_sd || len == 0)
        return false;
    if (g_log_handle_open) {
        if (R_FAILED(nupRawFileWrite(&g_log_file, g_log_pos, data, len, FsWriteOption_Flush)))
            return false;
        g_log_pos += (s64)len;
        nupRawFsCommit(g_log_sd);
        return true;
    }
    FsFile f = {};
    if (R_FAILED(nupRawFsOpenFile(g_log_sd, g_log_path, FsOpenMode_Write | FsOpenMode_Append, &f)))
        return false;
    const Result rc = nupRawFileWrite(&f, g_log_pos, data, len, FsWriteOption_Flush);
    serviceClose(&f.s);
    if (R_FAILED(rc))
        return false;
    g_log_pos += (s64)len;
    nupRawFsCommit(g_log_sd);
    return true;
}

static void ring_append_locked(const char* data, u32 len) {
    if (len == 0)
        return;
    if (len >= LOG_RING_SIZE) {
        data += (len - LOG_RING_SIZE);
        len = LOG_RING_SIZE;
        g_ring_head = 0;
        g_ring_count = 0;
    }
    if (g_ring_count + len > LOG_RING_SIZE) {
        const u32 drop = (g_ring_count + len) - LOG_RING_SIZE;
        g_ring_head = (g_ring_head + drop) % LOG_RING_SIZE;
        g_ring_count -= drop;
    }
    u32 tail = (g_ring_head + g_ring_count) % LOG_RING_SIZE;
    u32 first = LOG_RING_SIZE - tail;
    if (first > len) first = len;
    memcpy(g_ring + tail, data, first);
    if (len > first)
        memcpy(g_ring, data + first, len - first);
    g_ring_count += len;
}

static void ring_flush_locked(void) {
    if (!g_log_open || g_ring_count == 0)
        return;
    while (g_ring_count > 0) {
        u32 chunk = LOG_RING_SIZE - g_ring_head;
        if (chunk > g_ring_count) chunk = g_ring_count;
        if (!log_write_raw_locked(g_ring + g_ring_head, chunk))
            break;
        g_ring_head = (g_ring_head + chunk) % LOG_RING_SIZE;
        g_ring_count -= chunk;
    }
}

void nupLogInit(FsFileSystem* sd, const char* path) {
    nupSpinInit(&g_log_lock);
    g_log_sd = sd;
    g_log_path[0] = '\0';
    g_log_open = false;
    g_log_handle_open = false;
    g_log_persistent = false;
    g_log_pos = 0;
    g_ring_head = 0;
    g_ring_count = 0;
    if (!sd || !path)
        return;
    fsFsCreateDirectory(sd, "/kaihen");
    // Ensure any parent subdirectories (e.g. /kaihen/audits, /kaihen/traces) exist
    {
        char dir[FS_MAX_PATH];
        size_t plen = strlen(path);
        if (plen >= sizeof(dir)) plen = sizeof(dir) - 1;
        memcpy(dir, path, plen);
        dir[plen] = '\0';
        for (size_t i = 1; i < plen; i++) {
            if (dir[i] == '/') {
                dir[i] = '\0';
                fsFsCreateDirectory(sd, dir);
                dir[i] = '/';
            }
        }
    }
    snprintf(g_log_path, sizeof(g_log_path), "%s", path);
    fsFsDeleteFile(sd, path);
    if (R_FAILED(fsFsCreateFile(sd, path, 0, 0)))
        return;
    g_log_open = true;
    fsFsCommit(sd);
}

void nupLogSetPersistentHandle(bool keep_open) {
    nupSpinLock(&g_log_lock);
    if (g_log_open) {
        ring_flush_locked();
        if (keep_open && !g_log_handle_open) {
            if (R_SUCCEEDED(nupRawFsOpenFile(g_log_sd, g_log_path, FsOpenMode_Write | FsOpenMode_Append, &g_log_file)))
                g_log_handle_open = true;
        } else if (!keep_open && g_log_handle_open) {
            serviceClose(&g_log_file.s);
            g_log_handle_open = false;
        }
        g_log_persistent = keep_open;
    }
    nupSpinUnlock(&g_log_lock);
}

void nupLogBufferedf(const char* fmt, ...) {
    if (!g_log_open)
        return;
    char buf[512];
    nupSpinLock(&g_log_lock);
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_r(_impure_ptr, buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0 && g_log_open) {
        const u32 len = (u32)n < sizeof(buf) ? (u32)n : (u32)(sizeof(buf) - 1);
        ring_append_locked(buf, len);
    }
    nupSpinUnlock(&g_log_lock);
}

void nupLogFlush(void) {
    if (!g_log_open)
        return;
    nupSpinLock(&g_log_lock);
    ring_flush_locked();
    nupSpinUnlock(&g_log_lock);
}

void nupLogf(const char* fmt, ...) {
    if (!g_log_open)
        return;
    char buf[512];
    nupSpinLock(&g_log_lock);
    ring_flush_locked();
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_r(_impure_ptr, buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0 && g_log_open) {
        const size_t len = (size_t)n < sizeof(buf) ? (size_t)n : (sizeof(buf) - 1);
        log_write_raw_locked(buf, len);
    }
    nupSpinUnlock(&g_log_lock);
}

void nupLogClose(void) {
    nupSpinLock(&g_log_lock);
    if (g_log_open) {
        ring_flush_locked();
        if (g_log_handle_open) {
            fsFileFlush(&g_log_file);
            fsFileClose(&g_log_file);
            g_log_handle_open = false;
        }
        fsFsCommit(g_log_sd);
        g_log_open = false;
    }
    nupSpinUnlock(&g_log_lock);
}
