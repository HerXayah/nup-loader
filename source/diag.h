// SPDX-License-Identifier: MIT
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <switch.h>

u64 nupStripCodePac(u64 addr);
void nupFmtAddrMod(u64 addr, char* out, size_t sz);

void nupDiagReset(void);
void nupDiagRegisterExceptionHandler(bool force);
void nupDiagRegisterAbortObservers(void);
void nupDiagStartHeartbeat(void);
void nupDiagDumpLatestErpt(Handle hen_sm, FsFileSystem* sd);

void nupOnBeforeInitSdkModule(void);
void nupOnBeforeNninitStartup(void);
void nupOnBeforeNnMain(void);
void nupRecordWorkerThread(void* thread_type, void* fn);
void nupRecordWorkerThreadName(void* thread_type, const char* name);
void nupLogBacktrace(const char* tag, u64 caller, u64 arg0, u64 arg1);
