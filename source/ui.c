// SPDX-License-Identifier: MIT
#include "ui.h"
#include "nup.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>

static bool already_listed(const NupEntry* entries, int count, const char* path) {
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].path, path) == 0)
            return true;
    }
    return false;
}

static bool sd_is_dir(FsFileSystem* sd, const char* path) {
    u32 et = 0;
    return R_SUCCEEDED(nupRawFsGetEntryType(sd, path, &et)) && et == FsDirEntryType_Dir;
}

static void try_add_raw_entry(FsFileSystem* sd, const char* full_path,
                              const char* base_name, int prog_idx,
                              NupEntry* entries, int* count) {
    if (*count >= MAX_NUP_ENTRIES || already_listed(entries, *count, full_path))
        return;
    u64 tid = 0;
    u32 exefs_cnt = 0;
    if (!nupProbeRaw(sd, full_path, &tid, NULL, &exefs_cnt))
        return;
    NupEntry* e = &entries[(*count)++];
    memset(e, 0, sizeof(*e));
    if (prog_idx == 1) {
        snprintf(e->label, sizeof(e->label), "%.42s [Switch 2]", base_name);
    } else if (prog_idx > 1) {
        const char* tag = ((tid >> 56) == 0x04) ? "Switch 2 P" : "P";
        snprintf(e->label, sizeof(e->label), "%.38s [%s%d]", base_name, tag, prog_idx);
    } else {
        snprintf(e->label, sizeof(e->label), "%.54s", base_name);
    }
    snprintf(e->path, sizeof(e->path), "%s", full_path);
    e->title_id = tid;
    e->exefs_count = exefs_cnt;
}

static void scan_dir(FsFileSystem* sd, const char* dir_path,
                     NupEntry* entries, int* count) {
    DIR* dir = opendir(dir_path);
    if (!dir)
        return;
    struct dirent* item;
    while ((item = readdir(dir)) && *count < MAX_NUP_ENTRIES) {
        if (item->d_name[0] == '.')
            continue;
        char full[0x400];
        if (strcmp(dir_path, "/") == 0)
            snprintf(full, sizeof(full), "/%s", item->d_name);
        else
            snprintf(full, sizeof(full), "%s/%s", dir_path, item->d_name);

        if (!sd_is_dir(sd, full))
            continue;

        try_add_raw_entry(sd, full, item->d_name, 0, entries, count);
        // Multi-program dumps (e.g. Switch 2 Edition game/program1/exefs+romfs)
        char prog_parent[0x410];
        snprintf(prog_parent, sizeof(prog_parent), "%s/game", full);
        if (!sd_is_dir(sd, prog_parent))
            snprintf(prog_parent, sizeof(prog_parent), "%s", full);
        for (int p = 1; p <= 7 && *count < MAX_NUP_ENTRIES; p++) {
            char prog_dir[0x420];
            snprintf(prog_dir, sizeof(prog_dir), "%s/program%d", prog_parent, p);
            if (!sd_is_dir(sd, prog_dir))
                break;
            try_add_raw_entry(sd, prog_dir, item->d_name, p, entries, count);
        }
    }
    closedir(dir);
}

void nupUiScanAll(FsFileSystem* sd, NupEntry* entries, int* out_count,
                  char* skip_note, size_t skip_note_sz) {
    *out_count = 0;
    if (skip_note && skip_note_sz)
        skip_note[0] = '\0';
    static const char* const dirs[] = {
        "/switch/KaiDump/dumps", "/backups", "/games", "/nup", "/NUX", "/backups/nup", "/backups/NUX", "/"
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        scan_dir(sd, dirs[i], entries, out_count);
}

void nupUiDrawMenu(const NupEntry* entries, int count, int cursor,
                   const char* status, const char* skip_note) {
    consoleClear();
    printf("  kaiHEN Raw Game Loader (In-Process)\n");
    printf("  ===================================\n\n");
    if (count == 0) {
        printf("  No unpacked game folders found.\n");
        printf("  Place <App Name>/game/exefs+romfs in /switch/KaiDump/dumps, /backups, /games, /NUX, or /.\n\n");
    } else {
        for (int i = 0; i < count; i++) {
            const NupEntry* e = &entries[i];
            printf("  %s %016llx  %s (%u exefs)\n",
                   i == cursor ? ">" : " ",
                   (unsigned long long)e->title_id, e->label, e->exefs_count);
        }
        printf("\n");
    }
    printf("  Up/Down select   A Launch   Y Trace Launch   R Arm Native Loader   L Audit\n");
    printf("  X rescan         B/+ exit\n\n");
    if (status && status[0])
        printf("  %s\n", status);
    if (skip_note && skip_note[0])
        printf("  [!] %s\n", skip_note);
    consoleUpdate(NULL);
}

bool nupUiReadAutolaunch(FsFileSystem* sd, NupEntry* out, bool* out_trace, bool* out_was_once) {
    if (out_trace) *out_trace = false;
    if (out_was_once) *out_was_once = false;
    if (!sd) return false;
    FsFile f = {};
    if (R_FAILED(nupRawFsOpenFile(sd, "/kaihen/autolaunch.txt", FsOpenMode_Read, &f)))
        return false;
    char buf[0x400];
    memset(buf, 0, sizeof(buf));
    u64 got = 0;
    nupRawFileRead(&f, 0, buf, sizeof(buf) - 1, &got);
    serviceClose(&f.s);
    if (!got) return false;
    char* p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    char* end = p;
    while (*end && *end != '\r' && *end != '\n') end++;
    while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '/')) end--;
    *end = '\0';
    bool is_once = false;
    if (strncmp(p, "once:", 5) == 0) {
        is_once = true;
        p += 5;
        while (*p == ' ' || *p == '\t') p++;
        nupRawFsDeleteFile(sd, "/kaihen/autolaunch.txt");
    }
    if (out_was_once) *out_was_once = is_once;
    if (strncmp(p, "trace:", 6) == 0) {
        if (out_trace) *out_trace = true;
        p += 6;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (strncmp(p, "sdmc:", 5) == 0)
        p += 5;
    if (!p[0]) return false;

    memset(out, 0, sizeof(*out));
    snprintf(out->path, sizeof(out->path), "%s", p);
    const char* base = strrchr(p, '/');
    snprintf(out->label, sizeof(out->label), "%.54s", (base && base[1]) ? (base + 1) : p);
    if (!nupProbeRaw(sd, p, &out->title_id, NULL, &out->exefs_count))
        return false;
    return true;
}

Result nupUiWriteAutolaunchOnce(FsFileSystem* sd, const char* game_path, bool trace_mode) {
    if (!sd || !game_path || !game_path[0])
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    char line[0x420];
    const int n = snprintf(line, sizeof(line), "once:%s%s\n",
                           trace_mode ? "trace:" : "", game_path);
    if (n <= 0 || (size_t)n >= sizeof(line))
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    nupRawFsDeleteFile(sd, "/kaihen/autolaunch.txt");
    Result rc = nupRawFsCreateFile(sd, "/kaihen/autolaunch.txt", n, 0);
    if (R_FAILED(rc))
        return rc;
    FsFile f = {};
    rc = nupRawFsOpenFile(sd, "/kaihen/autolaunch.txt", FsOpenMode_Write, &f);
    if (R_FAILED(rc))
        return rc;
    rc = nupRawFileWrite(&f, 0, line, (u64)n, FsWriteOption_Flush);
    nupRawFileFlush(&f);
    serviceClose(&f.s);
    return rc;
}

bool nupUiProbeArgv(FsFileSystem* sd, int argc, char** argv, NupEntry* out, bool* out_trace) {
    if (out_trace) *out_trace = false;
    if (!sd || !out || argc < 2 || !argv)
        return false;

    const char* raw_arg = NULL;
    for (int i = 1; i < argc; i++) {
        if (!argv[i] || !argv[i][0])
            continue;
        if (strcmp(argv[i], "--trace") == 0 || strcmp(argv[i], "-t") == 0) {
            if (out_trace) *out_trace = true;
            continue;
        }
        if (!raw_arg)
            raw_arg = argv[i];
    }
    if (!raw_arg)
        return false;

    char clean[0x400];
    const char* p = raw_arg;
    if (strncmp(p, "trace:", 6) == 0) {
        if (out_trace) *out_trace = true;
        p += 6;
    }
    if (strncmp(p, "sdmc:", 5) == 0)
        p += 5;
    while (*p == ' ' || *p == '\t') p++;
    snprintf(clean, sizeof(clean), "%s", p);
    size_t len = strlen(clean);
    while (len > 1 && clean[len - 1] == '/')
        clean[--len] = '\0';
    if (!clean[0])
        return false;

    memset(out, 0, sizeof(*out));
    snprintf(out->path, sizeof(out->path), "%s", clean);
    const char* base = strrchr(clean, '/');
    snprintf(out->label, sizeof(out->label), "%.54s", (base && base[1]) ? (base + 1) : clean);
    return nupProbeRaw(sd, clean, &out->title_id, NULL, &out->exefs_count);
}
