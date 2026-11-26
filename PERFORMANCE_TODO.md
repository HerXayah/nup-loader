# `nup-loader` Performance Optimization TODOs

Tracked performance optimizations identified after `build=0325-feio9` / `build=0325-multi1` brought **Fire Emblem: Fortune's Weave** into full gameplay.

---

## Completed Baseline (`build=0325-multi1`)

- [x] **Removed worker-thread pause sampling in heartbeat thread** (`source/main.c:305-326`)
  - Removed periodic `svcSetThreadActivity(..., ThreadActivity_Paused)` + `svcGetThreadContext3` across worker threads so audio/video/I/O threads no longer stutter once per second.
- [x] **Fixed `cnt <= 50` concurrent-open log bug in `hook_OpenFile` (NUP path)** (`source/hooks.c:1168-1174`)
  - Replaced concurrent `g_open_file_count <= 50` check (which matched almost every `OpenFile` throughout gameplay) with total-count sampling (`tot <= 32 || tot % 250 == 0`) routed to `nupLogBufferedf`.

---

## High-Impact Runtime I/O & Threading Optimizations

- [ ] **1. Remove unconditional `svcGetThreadId` syscall on every `ReadFile` call** (`source/hooks.c:1231-1301`)
  - **Problem:** `hook_ReadFile6`, `hook_ReadFile5Out`, `hook_ReadFile5Opt`, and `hook_ReadFile4` call `svcGetThreadId(&tid, CUR_THREAD_HANDLE)` on **every single read**, even though `trace_read_begin` is now a no-op and `g_read_file_logs` stops at 8.
  - **Fix:** Gate `svcGetThreadId` behind `unlikely(g_read_file_logs < 8)` (or only on `R_FAILED(rc)`), eliminating thousands of unnecessary SVCs per second during asset/movie streaming.

- [ ] **2. Eliminate global `nup->io_lock` serialization on multi-threaded `.nup` reads** (`source/nup.c:534-551`, `source/nup.h:295-315`)
  - **Problem:** Every `nupReadFile()` acquires a single `nupSpinLock(&nup->io_lock)` (which sleeps `1 ms` per contended spin via `svcSleepThread(1000000LL)`) around `nupRawFileRead(&nup->file, ...)`. When `VideoDecoderThread` / `hwopus` streams video+audio simultaneously with 3–4 worker threads loading textures/shaders/models, all threads bottleneck on one lock.
  - **Fix:** Maintain a small pool of independent `FsFile` handles to the `.nup` archive (e.g., 4–6 handles indexed per-core or acquired lock-free) — or verify lock-free offset-based `IFile::Read` (`cmd 0`) concurrency on `fsp-srv` SD file handles — so multi-core RomFS reads run in parallel.

- [ ] **3. Replace newlib `snprintf` / `_vsnprintf_r(_impure_ptr, ...)` in hot hooks & logger** (`source/log.c:23-39`, `source/log.c:115-157`, `source/hooks.c:180-260`, `source/hooks.c:1110-1200`)
  - **Problem:** Game-created `nn::os` worker threads lack libnx `ThreadVars`, so any newlib `snprintf` / `_vsnprintf_r` hits `__wrap___getreent` and shares a single `_impure_ptr` across threads (`57,048+` hits observed in `feio9`). RAW/SD save path helpers (`format_sd_subpath`, `resolve_mount_sd_path_read`) also call `snprintf` on every `GetEntryType` / `OpenFile`.
  - **Fix:**
    1. Replace `snprintf` in `hooks.c` path concatenation with pure zero-reent byte-copy helpers (like `romfs-subsdk/source/main.c:786-817`).
    2. Replace `_vsnprintf_r` in `log.c` with a tiny freestanding formatter.
    3. Back `__wrap___getreent` with a small per-thread `struct _reent` table indexed by `tpidr_el0` (matching `tlsdesc_resolver` in `source/elf_loader.c:60-73`) so any remaining libc call is 100% lock-free and race-free.

- [ ] **4. Eliminate synchronous `nupLogf` + `FsWriteOption_Flush` + `nupRawFsCommit` during gameplay** (`source/log.c:139-157`, `source/hooks.c:1120-1157`, `source/hooks.c:1388-1580`, `source/main.c:322-325`)
  - **Problem:** `nupLogf()` flushes the ring buffer, writes with `FsWriteOption_Flush`, and executes `nupRawFsCommit(g_log_sd)` synchronously while holding `g_log_lock`. Runtime paths such as `OpenFile` `NOT FOUND` probes, `CreateFile*`, `CommitSaveData` (autosaves), and `SetThreadName` still call `nupLogf()`, stalling game threads on SD FAT commits. The heartbeat thread also wakes up every 2s forever even when `g_ring_count == 0`.
  - **Fix:** Switch all post-`nnMain` non-error logs to `nupLogBufferedf()` (or add a quiet/release toggle), flush without `fsFsCommit` except on save commits / abort / exit, and skip SD I/O in `heartbeat_thread_fn` when `g_ring_count == 0`.

- [ ] **5. Per-handle / LRU decompression cache for chunked Zstd (`codec == 1`) RomFS files** (`source/nup.c:511-532`)
  - **Problem:** When a game reads a `codec == 1` Zstd-compressed NUP file in small chunks (`offset != 0 || wanted != fe->size`), `nupReadFile` currently `malloc`s `comp_size` + `fe->size`, reads + decompresses the entire file on **every** chunk read, copies `wanted` bytes, and `free`s both buffers.
  - **Fix:** Attach an optional decompressed buffer (or small 2–4 entry shared LRU cache) to `OpenNupFile` so sequential chunked reads decompress once on first read and serve subsequent reads via `memcpy`, freeing on `CloseFile` / eviction.

---

## Boot Time & Memory Footprint Optimizations

- [ ] **6. Use `DT_GNU_HASH` / `DT_HASH` in `elfFindSymbol()` for `O(1)` relocation** (`source/elf_loader.c:174-175`, `source/elf_loader.c:381-402`)
  - **Problem:** `elfFindSymbol()` currently performs a linear `O(sym_count)` `strcmp` scan across every module (`sdk` has ~28,700 symbols) for each of the ~12,000 `DT_RELA` / `DT_JMPREL` imports (~340M symbol checks at startup).
  - **Fix:** `parse_mod0()` already records `mod->gnu_hash_off` and `mod->sysv_hash_off`! Implement standard GNU hash + SysV hash lookup in `elfFindSymbol()` to make symbol resolution `O(1)` (~50–100x faster boot relocation, especially once `compat2`'s 3,816 exports are added).

- [ ] **7. Binary search / hash index for large NUP TOC directories** (`source/nup.c:430-495`)
  - **Problem:** `nupLookupInDir()` linearly scans `d->child_count` entries per path component, and `nup_entry_shadowed()` linearly scans higher RomFS layers during `ReadDirectory` / `GetDirectoryEntryCount`.
  - **Fix:** Check at `nupOpenFull()` whether each directory's `children[]` slice is sorted (or sort an in-RAM index once) to use `O(log N)` binary search on large asset directories.

- [ ] **8. Minimize `keep` heap footprint before `svcSetHeapSize` shrink** (`source/main.c:795-837`, `source/elf_loader.c:233-336`)
  - **Problem:** Every MiB kept in `keep` reduces physical RAM available to Switch 1 `CompatibilityPack` (3.0 GiB pool) + the game's heap. Currently `nup_toc` + `src_buf` + `bss_buf` + temporary allocations determine the `high` watermark (`~296 MiB` on Z-A).
  - **Fix:** Allocate permanent NRO/BSS/TOC buffers from a compact low-address arena before any temporary buffers (or free temporary probe/UI allocations before `elfLoadNupModules`) so `high - heap_base` stays as tight as possible.
