// SPDX-License-Identifier: MIT
#include "nup.h"

#include <stdio.h>
#include <string.h>

static bool read_exact(FsFile* file, u64 offset, void* out, size_t size) {
    u64 done = 0;
    while (done < size) {
        const size_t chunk = (size - done) > 0x400000 ? 0x400000 : (size - done);
        u64 got = 0;
        const Result rc = nupRawFileRead(file, (s64)(offset + done),
                                         (u8*)out + done, chunk, &got);
        if (R_FAILED(rc) || got != chunk)
            return false;
        done += got;
    }
    return true;
}

static bool parse_npdm_title(const u8* buf, size_t len, u64* out_id) {
    for (size_t i = 0; i + 0x18 <= len; i++) {
        if (memcmp(buf + i, "ACI0", 4) != 0)
            continue;
        u64 id = 0;
        memcpy(&id, buf + i + 0x10, sizeof(id));
        if (id != 0) {
            *out_id = id;
            return true;
        }
    }
    return false;
}

static bool resolve_raw_game_dir(FsFileSystem* sd, const char* dir_path,
                                 char* out_game_dir, size_t out_sz) {
    char probe[FS_MAX_PATH];
    u32 et = 0;

    snprintf(probe, sizeof(probe), "%s/game/exefs", dir_path);
    if (R_SUCCEEDED(nupRawFsGetEntryType(sd, probe, &et)) && et == FsDirEntryType_Dir) {
        snprintf(out_game_dir, out_sz, "%s/game", dir_path);
        return true;
    }

    snprintf(probe, sizeof(probe), "%s/exefs", dir_path);
    if (R_SUCCEEDED(nupRawFsGetEntryType(sd, probe, &et)) && et == FsDirEntryType_Dir) {
        snprintf(out_game_dir, out_sz, "%s", dir_path);
        return true;
    }

    return false;
}

bool nupProbeRaw(FsFileSystem* sd, const char* dir_path, u64* out_title_id,
                 NupFileInfo* out_exefs, u32* out_exefs_count) {
    if (out_exefs_count)
        *out_exefs_count = 0;
    if (!sd || !dir_path || !dir_path[0])
        return false;

    char game_dir[0x300];
    if (!resolve_raw_game_dir(sd, dir_path, game_dir, sizeof(game_dir)))
        return false;

    char exefs_dir[FS_MAX_PATH];
    snprintf(exefs_dir, sizeof(exefs_dir), "%s/exefs", game_dir);

    FsDir dir = {};
    if (R_FAILED(nupRawFsOpenDir(sd, exefs_dir, FsDirOpenMode_ReadFiles, &dir)))
        return false;

    bool has_main = false;
    u32 count = 0;
    u64 tid = 0;
    FsDirectoryEntry entries[32];
    while (count < NUP_MAX_EXEFS_FILES) {
        s64 got = 0;
        if (R_FAILED(nupRawDirRead(&dir, &got, entries, 32)) || got <= 0)
            break;
        for (s64 i = 0; i < got && count < NUP_MAX_EXEFS_FILES; i++) {
            const char* name = entries[i].name;
            if (!name[0] || strlen(name) > NUP_MAX_NAME)
                continue;
            if (strcmp(name, "main") == 0)
                has_main = true;
            if (strcmp(name, "main.npdm") == 0 && out_title_id) {
                char npdm_path[FS_MAX_PATH];
                snprintf(npdm_path, sizeof(npdm_path), "%s/exefs/main.npdm", game_dir);
                FsFile nf = {};
                if (R_SUCCEEDED(nupRawFsOpenFile(sd, npdm_path, FsOpenMode_Read, &nf))) {
                    u8 npdm[0x1000];
                    u64 rd = 0;
                    if (R_SUCCEEDED(nupRawFileRead(&nf, 0, npdm, sizeof(npdm), &rd)) && rd > 0)
                        parse_npdm_title(npdm, (size_t)rd, &tid);
                    serviceClose(&nf.s);
                }
            }
            if (out_exefs) {
                memset(&out_exefs[count], 0, sizeof(out_exefs[count]));
                snprintf(out_exefs[count].name, sizeof(out_exefs[count].name), "%s", name);
                out_exefs[count].size = (u64)entries[i].file_size;
            }
            count++;
        }
    }
    serviceClose(&dir.s);

    if (!has_main)
        return false;
    if (out_title_id)
        *out_title_id = tid;
    if (out_exefs_count)
        *out_exefs_count = count;
    return true;
}

static bool strip_program_subdir_tail(const char* path, char* out_parent, size_t out_sz) {
    const size_t len = strlen(path);
    // Match trailing "/program<1..9>"
    if (len < 10)
        return false;
    const char last = path[len - 1];
    if (last < '1' || last > '9')
        return false;
    if (strncmp(path + len - 9, "/program", 8) != 0)
        return false;
    const size_t pfx = len - 9;
    if (pfx == 0) {
        snprintf(out_parent, out_sz, "/");
    } else {
        const size_t n = pfx < out_sz - 1 ? pfx : out_sz - 1;
        memcpy(out_parent, path, n);
        out_parent[n] = '\0';
    }
    return true;
}

Result nupOpenRaw(NupArchive* nup, FsFileSystem* sd, const char* dir_path) {
    memset(nup, 0, sizeof(*nup));
    nup->raw_sd = sd;
    nup->open = true;
    snprintf(nup->raw_app_root, sizeof(nup->raw_app_root), "%s", dir_path);
    if (!resolve_raw_game_dir(sd, dir_path, nup->raw_root, sizeof(nup->raw_root)))
        snprintf(nup->raw_root, sizeof(nup->raw_root), "%s", dir_path);

    char sub_parent[0x300] = {};
    if (strip_program_subdir_tail(nup->raw_root, sub_parent, sizeof(sub_parent))) {
        nup->raw_is_subprogram = true;
        // Derive app root above optional "/game" parent so shared "<App>/dlc" is discovered.
        const size_t plen = strlen(sub_parent);
        if (plen > 5 && strcmp(sub_parent + plen - 5, "/game") == 0) {
            const size_t alen = plen - 5;
            const size_t n = alen < sizeof(nup->raw_app_root) - 1 ? alen : sizeof(nup->raw_app_root) - 1;
            memcpy(nup->raw_app_root, sub_parent, n);
            nup->raw_app_root[n] = '\0';
        } else {
            snprintf(nup->raw_app_root, sizeof(nup->raw_app_root), "%s", sub_parent);
        }
    }

    char romfs_dir[0x300];
    snprintf(romfs_dir, sizeof(romfs_dir), "%.755s/romfs", nup->raw_root);
    u32 etype = 0;
    if (R_SUCCEEDED(nupRawFsGetEntryType(sd, romfs_dir, &etype)) && etype == FsDirEntryType_Dir) {
        nup->has_romfs = true;
        memcpy(nup->raw_romfs_root, romfs_dir, sizeof(nup->raw_romfs_root));
    } else if (nup->raw_is_subprogram && sub_parent[0]) {
        // Fallback to parent game/romfs when a multi-program dump shares a single romfs.
        snprintf(romfs_dir, sizeof(romfs_dir), "%.755s/romfs", sub_parent);
        if (R_SUCCEEDED(nupRawFsGetEntryType(sd, romfs_dir, &etype)) && etype == FsDirEntryType_Dir) {
            nup->has_romfs = true;
            memcpy(nup->raw_romfs_root, romfs_dir, sizeof(nup->raw_romfs_root));
        }
    }
    return 0;
}

void nupClose(NupArchive* nup) {
    if (nup)
        nup->open = false;
}

Result nupReadExefs(NupArchive* nup, const NupFileInfo* fi, u64 offset, void* dst, size_t size) {
    if (!nup || !nup->open || !fi)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    char fpath[FS_MAX_PATH];
    snprintf(fpath, sizeof(fpath), "%s/exefs/%s", nup->raw_root, fi->name);
    FsFile f = {};
    Result rc = nupRawFsOpenFile(nup->raw_sd, fpath, FsOpenMode_Read, &f);
    if (R_FAILED(rc))
        return rc;
    const bool ok = read_exact(&f, offset, dst, size);
    serviceClose(&f.s);
    return ok ? 0 : MAKERESULT(Module_Libnx, LibnxError_IoError);
}

void nupFormatRawRomPath(const NupArchive* nup, const char* rel_path, char* out, size_t out_sz) {
    const char* p = rel_path ? rel_path : "";
    while (*p == '/')
        p++;
    if (nup->raw_romfs_root[0]) {
        if (*p)
            snprintf(out, out_sz, "%s/%s", nup->raw_romfs_root, p);
        else
            snprintf(out, out_sz, "%s", nup->raw_romfs_root);
    } else if (*p) {
        snprintf(out, out_sz, "%s/romfs/%s", nup->raw_root, p);
    } else {
        snprintf(out, out_sz, "%s/romfs", nup->raw_root);
    }
    // Strip trailing slashes (Switch FS rejects trailing '/' on non-root paths).
    size_t len = strlen(out);
    while (len > 1 && out[len - 1] == '/')
        out[--len] = '\0';
}
