// SPDX-License-Identifier: GPL-2.0-only
#include "zbic.h"

#define ZSTD_STATIC_LINKING_ONLY
#define ZSTD_ZBIC_SUPPORT 1
#define ZSTD_DISABLE_ASM 1

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#define ZSTDLIB_VISIBLE static
#define ZSTDLIB_HIDDEN  static
#include "zbic/zstd.h"
#include "zbic/zstd.inc"
#pragma GCC diagnostic pop

bool zbicDecompress(void* dst, size_t dst_size, const void* src, size_t src_size) {
    if (!dst || !src || !dst_size || !src_size)
        return false;
    const size_t rc = ZSTD_decompress(dst, dst_size, src, src_size);
    return !ZSTD_isError(rc) && rc == dst_size;
}
