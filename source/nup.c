// SPDX-License-Identifier: MIT
#include "nup.h"
#include "zbic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool part_code_better(const NupPartEntry* a, u32 ai, const NupPartEntry* b, u32 bi) {
    const int a_s2 = ((a->title_id >> 56) == 0x04) ? 1 : 0;
    const int b_s2 = ((b->title_id >> 56) == 0x04) ? 1 : 0;
    if (a_s2 != b_s2) return a_s2 > b_s2;
    const int a_upd = (a->kind != 0) ? 1 : 0;
    const int b_upd = (b->kind != 0) ? 1 : 0;
    if (a_upd != b_upd) return a_upd > b_upd;
    if (a->version != b->version) return a->version > b->version;
    return ai > bi;
}

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

static char g_probe_err[128] = {};

const char* nupLastProbeError(void) {
    return g_probe_err;
}

static bool find_exefs_dir_rec(FsFile* file, u64 dir_base, u64 dir_count,
                               u64 child_base, u64 str_base, u64 str_size,
                               const NupDirEntry* cur, int depth,
                               NupDirEntry* out_exefs) {
    if (depth > 3)
        return false;
    const u32 scan = cur->child_count < 64 ? cur->child_count : 64;
    for (u32 i = 0; i < scan; i++) {
        u32 node = 0;
        if (!read_exact(file, child_base + (u64)(cur->first_child + i) * 4, &node, 4))
            break;
        if (node >= dir_count)
            continue;
        NupDirEntry d = {};
        if (!read_exact(file, dir_base + (u64)node * sizeof(NupDirEntry), &d, sizeof(d)))
            continue;
        if (d.name_len == 5 && (u64)d.name_off + 5 <= str_size) {
            char name[5];
            if (read_exact(file, str_base + d.name_off, name, 5) &&
                memcmp(name, "exefs", 5) == 0) {
                *out_exefs = d;
                return true;
            }
        }
    }
    if (depth < 3) {
        for (u32 i = 0; i < scan; i++) {
            u32 node = 0;
            if (!read_exact(file, child_base + (u64)(cur->first_child + i) * 4, &node, 4))
                break;
            if (node >= dir_count)
                continue;
            NupDirEntry d = {};
            if (!read_exact(file, dir_base + (u64)node * sizeof(NupDirEntry), &d, sizeof(d)))
                continue;
            if (find_exefs_dir_rec(file, dir_base, dir_count, child_base,
                                   str_base, str_size, &d, depth + 1, out_exefs))
                return true;
        }
    }
    return false;
}

static bool find_named_dir_rec(const NupArchive* nup, u32 cur_idx, const char* target,
                               int depth, u32* out_idx) {
    if (depth > 3 || cur_idx >= nup->dir_count)
        return false;
    const size_t tlen = strlen(target);
    const NupDirEntry* d = &nup->dirs[cur_idx];
    for (u32 i = 0; i < d->child_count; i++) {
        const u32 node = nup->children[d->first_child + i];
        if (node >= nup->dir_count)
            continue;
        const NupDirEntry* cd = &nup->dirs[node];
        if (cd->name_len == tlen && memcmp(nup->strings + cd->name_off, target, tlen) == 0) {
            *out_idx = node;
            return true;
        }
    }
    if (depth < 3) {
        for (u32 i = 0; i < d->child_count; i++) {
            const u32 node = nup->children[d->first_child + i];
            if (node >= nup->dir_count)
                continue;
            if (find_named_dir_rec(nup, node, target, depth + 1, out_idx))
                return true;
        }
    }
    return false;
}

bool nupProbe(FsFileSystem* sd, const char* path, u64* out_title_id,
              NupFileInfo* out_exefs, u32* out_exefs_count) {
    g_probe_err[0] = '\0';
    if (out_exefs_count)
        *out_exefs_count = 0;
    FsFile file = {};
    Result rc = fsFsOpenFile(sd, path, FsOpenMode_Read, &file);
    if (R_FAILED(rc)) {
        snprintf(g_probe_err, sizeof(g_probe_err), "open failed 0x%x", rc);
        return false;
    }

    bool ok = false;
    u8 hdr[0x80];
    u8 toc_hdr[0x30];
    if (!read_exact(&file, 0, hdr, sizeof(hdr))) {
        snprintf(g_probe_err, sizeof(g_probe_err), "hdr read failed");
        goto done;
    }
    if (memcmp(hdr, "NUP\x01", 4) != 0) {
        snprintf(g_probe_err, sizeof(g_probe_err), "bad magic %02x%02x%02x%02x",
                 hdr[0], hdr[1], hdr[2], hdr[3]);
        goto done;
    }

    u64 toc_off = 0, toc_size = 0;
    memcpy(&toc_off, hdr + 0x08, 8);
    memcpy(&toc_size, hdr + 0x10, 8);
    if (toc_size < sizeof(toc_hdr) + sizeof(NupPartEntry) + sizeof(NupDirEntry)) {
        snprintf(g_probe_err, sizeof(g_probe_err), "toc_size too small (%llu)", (unsigned long long)toc_size);
        goto done;
    }

    if (!read_exact(&file, toc_off, toc_hdr, sizeof(toc_hdr))) {
        snprintf(g_probe_err, sizeof(g_probe_err), "toc read failed off=0x%llx", (unsigned long long)toc_off);
        goto done;
    }
    if (memcmp(toc_hdr, "TOC\x01", 4) != 0) {
        snprintf(g_probe_err, sizeof(g_probe_err), "bad toc magic %02x%02x%02x%02x",
                 toc_hdr[0], toc_hdr[1], toc_hdr[2], toc_hdr[3]);
        goto done;
    }

    u32 part_count = 0;
    u64 dir_count = 0, file_count = 0, str_off = 0, str_size = 0;
    memcpy(&part_count, toc_hdr + 0x04, 4);
    memcpy(&dir_count, toc_hdr + 0x08, 8);
    memcpy(&file_count, toc_hdr + 0x10, 8);
    memcpy(&str_off, toc_hdr + 0x18, 8);
    memcpy(&str_size, toc_hdr + 0x20, 8);
    if (part_count == 0 || part_count > 128 || dir_count < 2 || file_count < 2 ||
        str_off > toc_size || str_size > toc_size - str_off) {
        snprintf(g_probe_err, sizeof(g_probe_err), "bad counts p=%u d=%llu f=%llu",
                 part_count, (unsigned long long)dir_count, (unsigned long long)file_count);
        goto done;
    }

    const u64 part_base = toc_off + 0x30;
    const u64 dir_base = part_base + (u64)part_count * sizeof(NupPartEntry);
    const u64 file_base = dir_base + dir_count * sizeof(NupDirEntry);
    const u64 child_base = file_base + file_count * sizeof(NupFileEntry);
    const u64 str_base = toc_off + str_off;
    if (child_base > str_base) {
        snprintf(g_probe_err, sizeof(g_probe_err), "child_base > str_base");
        goto done;
    }

    u64 toc_title = 0;
    u32 exefs_idx = 0xFFFFFFFFu;
    NupPartEntry best_pe = {};
    u32 best_pi = 0;
    bool have_best = false;
    for (u32 pi = 0; pi < part_count; pi++) {
        NupPartEntry pe = {};
        if (!read_exact(&file, part_base + (u64)pi * sizeof(NupPartEntry), &pe, sizeof(pe)))
            break;
        if (pi == 0)
            toc_title = pe.title_id;
        if (pe.exefs_dir_idx < dir_count) {
            if (!have_best || part_code_better(&pe, pi, &best_pe, best_pi)) {
                best_pe = pe;
                best_pi = pi;
                have_best = true;
                exefs_idx = pe.exefs_dir_idx;
                if (pe.title_id)
                    toc_title = pe.title_id;
            }
        }
    }

    NupDirEntry exefs_dir = {};
    if (exefs_idx < dir_count) {
        if (!read_exact(&file, dir_base + (u64)exefs_idx * sizeof(NupDirEntry),
                        &exefs_dir, sizeof(exefs_dir))) {
            snprintf(g_probe_err, sizeof(g_probe_err), "exefs dir read failed");
            goto done;
        }
    } else {
        NupDirEntry root = {};
        if (!read_exact(&file, dir_base, &root, sizeof(root)) ||
            !find_exefs_dir_rec(&file, dir_base, dir_count, child_base, str_base, str_size,
                                &root, 0, &exefs_dir)) {
            snprintf(g_probe_err, sizeof(g_probe_err), "no exefs dir (parts=%u)", part_count);
            goto done;
        }
    }
    if (exefs_dir.child_count < 2) {
        snprintf(g_probe_err, sizeof(g_probe_err), "exefs too few files (%u)", exefs_dir.child_count);
        goto done;
    }

    u32 count = 0;
    bool has_main = false;
    u64 npdm_off = 0, npdm_size = 0;
    for (u32 i = 0; i < exefs_dir.child_count && count < NUP_MAX_EXEFS_FILES; i++) {
        u32 node = 0;
        if (!read_exact(&file, child_base + (u64)(exefs_dir.first_child + i) * 4, &node, 4))
            break;
        if (node < dir_count || node >= dir_count + file_count)
            continue;
        NupFileEntry fe = {};
        if (!read_exact(&file, file_base + (u64)(node - dir_count) * sizeof(NupFileEntry),
                        &fe, sizeof(fe)))
            continue;
        if (fe.name_len == 0 || fe.name_len > NUP_MAX_NAME ||
            (u64)fe.name_off + fe.name_len > str_size)
            continue;
        char fname[NUP_MAX_NAME + 1] = {};
        if (!read_exact(&file, str_base + fe.name_off, fname, fe.name_len))
            continue;
        fname[fe.name_len] = '\0';
        if (strcmp(fname, "main") == 0)
            has_main = true;
        if (strcmp(fname, "main.npdm") == 0) {
            npdm_off = fe.data_off;
            npdm_size = fe.codec == 1 ? fe.comp_size : fe.size;
            if (fe.codec == 1) npdm_size = 0; // fall back to toc_title if npdm is zstd
        }
        if (out_exefs) {
            memset(&out_exefs[count], 0, sizeof(out_exefs[count]));
            memcpy(out_exefs[count].name, fname, fe.name_len + 1);
            out_exefs[count].size = fe.size;
            out_exefs[count].offset = fe.data_off;
            out_exefs[count].comp_size = fe.comp_size;
            out_exefs[count].codec = fe.codec;
        }
        count++;
    }
    if (!has_main) {
        snprintf(g_probe_err, sizeof(g_probe_err), "no main in exefs (cnt=%u)", count);
        goto done;
    }

    if (out_title_id) {
        u64 tid = 0;
        if (npdm_size > 0) {
            u8 npdm[0x1000];
            const size_t n = npdm_size < sizeof(npdm) ? (size_t)npdm_size : sizeof(npdm);
            if (read_exact(&file, npdm_off, npdm, n))
                parse_npdm_title(npdm, n, &tid);
        }
        *out_title_id = tid ? tid : toc_title;
    }
    if (out_exefs_count)
        *out_exefs_count = count;
    ok = true;

done:
    fsFileClose(&file);
    return ok;
}

Result nupOpenFull(NupArchive* nup, FsFileSystem* sd, const char* path) {
    memset(nup, 0, sizeof(*nup));
    nupSpinInit(&nup->io_lock);

    Result rc = fsFsOpenFile(sd, path, FsOpenMode_Read, &nup->file);
    if (R_FAILED(rc))
        return rc;
    nup->open = true;

    u8 hdr[0x80];
    if (!read_exact(&nup->file, 0, hdr, sizeof(hdr)) || memcmp(hdr, "NUP\x01", 4) != 0) {
        nupClose(nup);
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }
    memcpy(&nup->toc_off, hdr + 0x08, 8);
    memcpy(&nup->toc_size, hdr + 0x10, 8);
    if (nup->toc_size < 0x80 || nup->toc_size > 0x10000000ull) {
        nupClose(nup);
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }

    nup->toc_buf = (u8*)malloc((size_t)nup->toc_size);
    if (!nup->toc_buf) {
        nupClose(nup);
        return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    }
    if (!read_exact(&nup->file, nup->toc_off, nup->toc_buf, (size_t)nup->toc_size) ||
        memcmp(nup->toc_buf, "TOC\x01", 4) != 0) {
        nupClose(nup);
        return MAKERESULT(Module_Libnx, LibnxError_IoError);
    }

    memcpy(&nup->part_count, nup->toc_buf + 0x04, 4);
    memcpy(&nup->dir_count, nup->toc_buf + 0x08, 8);
    memcpy(&nup->file_count, nup->toc_buf + 0x10, 8);
    memcpy(&nup->str_off, nup->toc_buf + 0x18, 8);
    memcpy(&nup->str_size, nup->toc_buf + 0x20, 8);

    const u64 dir_rel = 0x30 + (u64)nup->part_count * sizeof(NupPartEntry);
    const u64 file_rel = dir_rel + nup->dir_count * sizeof(NupDirEntry);
    const u64 child_rel = file_rel + nup->file_count * sizeof(NupFileEntry);
    if (nup->part_count == 0 || nup->part_count > 128 || nup->dir_count < 2 ||
        nup->str_off > nup->toc_size ||
        nup->str_size > nup->toc_size - nup->str_off ||
        child_rel > nup->str_off) {
        nupClose(nup);
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }

    nup->parts = (const NupPartEntry*)(nup->toc_buf + 0x30);
    nup->dirs = (const NupDirEntry*)(nup->toc_buf + dir_rel);
    nup->files = (const NupFileEntry*)(nup->toc_buf + file_rel);
    nup->children = (const u32*)(nup->toc_buf + child_rel);
    nup->strings = (const char*)(nup->toc_buf + nup->str_off);

    nup->title_id = nup->parts[0].title_id;
    u32 best_pi = 0;
    bool have_best = false;
    u32 layer_pis[NUP_MAX_ROMFS_LAYERS];
    u32 layer_cnt = 0;
    for (u32 pi = 0; pi < nup->part_count; pi++) {
        const NupPartEntry* pe = &nup->parts[pi];
        if (pe->exefs_dir_idx < nup->dir_count) {
            if (!have_best || part_code_better(pe, pi, &nup->parts[best_pi], best_pi)) {
                best_pi = pi;
                have_best = true;
                if (pe->title_id)
                    nup->title_id = pe->title_id;
            }
        }
        // Include base (kind 0), updates (kind 1), and any code-bearing upgrade (e.g. Switch 2 Edition) in RomFS overlay
        if (pe->romfs_dir_idx < nup->dir_count &&
            (pe->kind == 0 || pe->kind == 1 || pe->exefs_dir_idx < nup->dir_count)) {
            if (layer_cnt < NUP_MAX_ROMFS_LAYERS)
                layer_pis[layer_cnt++] = pi;
        }
    }
    // Sort RomFS layers newest-first (Switch 2 Edition / highest update version first, base game last)
    for (u32 i = 1; i < layer_cnt; i++) {
        u32 key = layer_pis[i];
        int j = (int)i - 1;
        while (j >= 0 && part_code_better(&nup->parts[key], key, &nup->parts[layer_pis[j]], layer_pis[j])) {
            layer_pis[j + 1] = layer_pis[j];
            j--;
        }
        layer_pis[j + 1] = key;
    }
    for (u32 i = 0; i < layer_cnt; i++)
        nup->romfs_dirs[i] = nup->parts[layer_pis[i]].romfs_dir_idx;
    nup->romfs_layer_count = layer_cnt;
    if (layer_cnt > 0) {
        nup->romfs_dir_idx = nup->romfs_dirs[0];
        nup->has_romfs = true;
    }
    if (!nup->has_romfs) {
        u32 rom_idx = 0;
        if (find_named_dir_rec(nup, 0, "romfs", 0, &rom_idx)) {
            nup->romfs_dir_idx = rom_idx;
            nup->romfs_dirs[0] = rom_idx;
            nup->romfs_layer_count = 1;
            nup->has_romfs = true;
        }
    }
    u32 dlc_idx = 0;
    if (find_named_dir_rec(nup, 0, "dlc", 0, &dlc_idx) ||
        find_named_dir_rec(nup, 0, "aoc", 0, &dlc_idx)) {
        nup->dlc_dir_idx = dlc_idx;
        nup->has_dlc = true;
    }
    return 0;
}

void nupClose(NupArchive* nup) {
    if (nup->toc_buf) {
        free(nup->toc_buf);
        nup->toc_buf = NULL;
    }
    if (nup->open) {
        fsFileClose(&nup->file);
        nup->open = false;
    }
}

bool nupLookupInDir(const NupArchive* nup, u32 root_dir_idx, const char* rel_path,
                    bool* out_is_dir, u32* out_idx) {
    if (!nup || !nup->open || nup->is_raw || root_dir_idx >= nup->dir_count || !rel_path)
        return false;

    const char* p = rel_path;
    while (*p == '/')
        p++;

    u32 cur_dir = root_dir_idx;
    if (*p == '\0') {
        *out_is_dir = true;
        *out_idx = cur_dir;
        return true;
    }

    while (*p) {
        const char* slash = strchr(p, '/');
        const size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);
        if (comp_len == 0) {
            p = slash + 1;
            continue;
        }
        const bool last = (!slash || slash[1] == '\0');
        const NupDirEntry* d = &nup->dirs[cur_dir];
        bool matched = false;
        for (u32 i = 0; i < d->child_count; i++) {
            const u32 node = nup->children[d->first_child + i];
            if (node < nup->dir_count) {
                const NupDirEntry* cd = &nup->dirs[node];
                if (cd->name_len == comp_len &&
                    memcmp(nup->strings + cd->name_off, p, comp_len) == 0) {
                    if (last) {
                        *out_is_dir = true;
                        *out_idx = node;
                        return true;
                    }
                    cur_dir = node;
                    matched = true;
                    break;
                }
            } else if (node < nup->dir_count + nup->file_count) {
                const u32 fidx = (u32)(node - nup->dir_count);
                const NupFileEntry* cf = &nup->files[fidx];
                if (cf->name_len == comp_len &&
                    memcmp(nup->strings + cf->name_off, p, comp_len) == 0) {
                    if (last) {
                        *out_is_dir = false;
                        *out_idx = fidx;
                        return true;
                    }
                    return false;
                }
            }
        }
        if (!matched)
            return false;
        p = slash + 1;
        while (*p == '/')
            p++;
    }
    *out_is_dir = true;
    *out_idx = cur_dir;
    return true;
}

bool nupLookupRomfs(const NupArchive* nup, const char* rel_path,
                    bool* out_is_dir, u32* out_idx) {
    if (!nup || !nup->has_romfs)
        return false;
    for (u32 i = 0; i < nup->romfs_layer_count; i++) {
        if (nupLookupInDir(nup, nup->romfs_dirs[i], rel_path, out_is_dir, out_idx))
            return true;
    }
    return nupLookupInDir(nup, nup->romfs_dir_idx, rel_path, out_is_dir, out_idx);
}

Result nupReadFile(NupArchive* nup, u32 file_idx, s64 offset, void* dst,
                   size_t size, size_t* out_read) {
    if (out_read)
        *out_read = 0;
    if (!nup || !nup->open || file_idx >= nup->file_count || offset < 0)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);

    const NupFileEntry* fe = &nup->files[file_idx];
    if ((u64)offset >= fe->size || size == 0)
        return 0;

    u64 avail = fe->size - (u64)offset;
    u64 wanted = (u64)size < avail ? (u64)size : avail;

    if (fe->codec == 1 && fe->comp_size > 0) {
        u8* cbuf = (u8*)malloc((size_t)fe->comp_size);
        if (!cbuf) return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
        Result rc = nupReadRaw(nup, fe->data_off, cbuf, (size_t)fe->comp_size);
        if (R_FAILED(rc)) { free(cbuf); return rc; }
        if (offset == 0 && wanted == fe->size) {
            const bool ok = zbicDecompress(dst, (size_t)fe->size, cbuf, (size_t)fe->comp_size);
            free(cbuf);
            if (!ok) return MAKERESULT(Module_Libnx, LibnxError_IoError);
            if (out_read) *out_read = (size_t)wanted;
            return 0;
        }
        u8* ubuf = (u8*)malloc((size_t)fe->size);
        if (!ubuf) { free(cbuf); return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory); }
        const bool ok = zbicDecompress(ubuf, (size_t)fe->size, cbuf, (size_t)fe->comp_size);
        free(cbuf);
        if (!ok) { free(ubuf); return MAKERESULT(Module_Libnx, LibnxError_IoError); }
        memcpy(dst, ubuf + offset, (size_t)wanted);
        free(ubuf);
        if (out_read) *out_read = (size_t)wanted;
        return 0;
    }

    nupSpinLock(&nup->io_lock);
    u64 total = 0;
    Result rc = 0;
    while (total < wanted) {
        u64 chunk = wanted - total;
        if (chunk > 0x400000)
            chunk = 0x400000;
        u64 got = 0;
        rc = nupRawFileRead(&nup->file, (s64)(fe->data_off + (u64)offset + total),
                            (u8*)dst + total, chunk, &got);
        if (R_FAILED(rc))
            break;
        total += got;
        if (got < chunk)
            break;
    }
    nupSpinUnlock(&nup->io_lock);

    if (out_read)
        *out_read = (size_t)total;
    return rc;
}

Result nupReadRaw(NupArchive* nup, u64 offset, void* dst, size_t size) {
    if (!nup || !nup->open)
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    nupSpinLock(&nup->io_lock);
    const bool ok = read_exact(&nup->file, offset, dst, size);
    nupSpinUnlock(&nup->io_lock);
    return ok ? 0 : MAKERESULT(Module_Libnx, LibnxError_IoError);
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
                out_exefs[count].offset = 0;
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
    nupSpinInit(&nup->io_lock);
    nup->is_raw = true;
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

Result nupReadExefs(NupArchive* nup, const NupFileInfo* fi, u64 offset, void* dst, size_t size) {
    if (!nup || !fi)
        return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    if (!nup->is_raw) {
        if (fi->codec == 1 && fi->comp_size > 0) {
            if (offset + size > fi->size)
                return MAKERESULT(Module_Libnx, LibnxError_BadInput);
            u8* cbuf = (u8*)malloc((size_t)fi->comp_size);
            if (!cbuf) return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
            Result rc = nupReadRaw(nup, fi->offset, cbuf, (size_t)fi->comp_size);
            if (R_FAILED(rc)) { free(cbuf); return rc; }
            if (offset == 0 && size == fi->size) {
                const bool ok = zbicDecompress(dst, (size_t)fi->size, cbuf, (size_t)fi->comp_size);
                free(cbuf);
                return ok ? 0 : MAKERESULT(Module_Libnx, LibnxError_IoError);
            }
            u8* ubuf = (u8*)malloc((size_t)fi->size);
            if (!ubuf) { free(cbuf); return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory); }
            const bool ok = zbicDecompress(ubuf, (size_t)fi->size, cbuf, (size_t)fi->comp_size);
            free(cbuf);
            if (!ok) { free(ubuf); return MAKERESULT(Module_Libnx, LibnxError_IoError); }
            memcpy(dst, ubuf + offset, size);
            free(ubuf);
            return 0;
        }
        return nupReadRaw(nup, fi->offset + offset, dst, size);
    }

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
