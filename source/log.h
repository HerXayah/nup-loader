// SPDX-License-Identifier: MIT
#pragma once

#include <switch.h>

void nupLogInit(FsFileSystem* sd, const char* path);
void nupLogSetPersistentHandle(bool keep_open);
void nupLogf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void nupLogBufferedf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void nupLogFlush(void);
void nupLogClose(void);
