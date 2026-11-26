// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>

bool zbicDecompress(void* dst, size_t dst_size, const void* src, size_t src_size);
