// SPDX-License-Identifier: MIT
// Low-level AArch64 SVC interception trampoline with private handler stack pool.
// Every patched `svc #n` in a loaded NSO branches to a 24-byte thunk in NRO page 0
// that saves (x16, x30), puts `n` in w16, and `blr`s here.
//
// Why a private stack pool: real kernel SVCs consume zero user stack, so games often
// spawn worker threads with tiny (4-8 KiB) stacks that would overflow if C IPC/SD
// handlers ran directly on the game thread's stack.

    .set NUP_SVC_STACKS, 32
    .set NUP_SVC_STACK_SHIFT, 16        // 64 KiB per handler stack (2 MiB total in .bss)

    .section .bss.nup_svc_stacks, "aw", %nobits
    .balign 16
nup_svc_stack_mem:
    .space (NUP_SVC_STACKS << NUP_SVC_STACK_SHIFT)
nup_svc_stack_used:
    .space NUP_SVC_STACKS

    .section .text.nup_svc_entry, "ax", %progbits
    .balign 4
    .global nup_svc_entry
    .type nup_svc_entry, %function
nup_svc_entry:
    // Save GPRs (x0-x18, x29, x30, x16) + SIMD caller-saved (q0-q7) so C code / memcpy
    // inside nupSvcDispatch can never clobber game floating-point/NEON registers.
    sub sp, sp, #304
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x17, x18, [sp, #128]
    stp x29, x30, [sp, #144]
    str x16,      [sp, #160]
    stp q0,  q1,  [sp, #176]
    stp q2,  q3,  [sp, #208]
    stp q4,  q5,  [sp, #240]
    stp q6,  q7,  [sp, #272]

    // Arguments to nupSvcDispatch(u64* regs, u32 svc_num)
    mov x0, sp
    mov w1, w16

    // Acquire a 64 KiB private stack atomically (fall back to caller stack if pool full)
    adrp x9, nup_svc_stack_used
    add  x9, x9, :lo12:nup_svc_stack_used
    mov  x10, #0
1:
    add  x12, x9, x10
2:
    ldaxrb w13, [x12]
    cbnz w13, 3f
    mov  w14, #1
    stlxrb w15, w14, [x12]
    cbnz w15, 2b
    b    4f
3:
    clrex
    add  x10, x10, #1
    cmp  x10, #NUP_SVC_STACKS
    b.ne 1b
    // Pool exhausted: run on caller stack
    bl   nupSvcDispatch
    b    5f
4:
    adrp x11, nup_svc_stack_mem
    add  x11, x11, :lo12:nup_svc_stack_mem
    add  x10, x10, #1
    add  x11, x11, x10, lsl #NUP_SVC_STACK_SHIFT
    mov  x13, sp
    mov  sp, x11
    stp  x13, x12, [sp, #-16]!
    bl   nupSvcDispatch
    ldp  x13, x12, [sp], #16
    mov  sp, x13
    stlrb wzr, [x12]
5:
    // w0 != 0 => handled (return regs[0..7]); w0 == 0 => execute real SVC stub
    cbnz w0, 6f
    ldr  x16, [sp, #160]
    cmp  x16, #0xC0
    b.hs 6f
    adrp x17, nup_svc_stubs
    add  x17, x17, :lo12:nup_svc_stubs
    add  x17, x17, x16, lsl #3
    ldp  x0, x1, [sp, #0]
    ldp  x2, x3, [sp, #16]
    ldp  x4, x5, [sp, #32]
    ldp  x6, x7, [sp, #48]
    blr  x17
    b    7f
6:
    ldp  x0, x1, [sp, #0]
    ldp  x2, x3, [sp, #16]
    ldp  x4, x5, [sp, #32]
    ldp  x6, x7, [sp, #48]
7:
    ldp  q0,  q1,  [sp, #176]
    ldp  q2,  q3,  [sp, #208]
    ldp  q4,  q5,  [sp, #240]
    ldp  q6,  q7,  [sp, #272]
    ldp  x8,  x9,  [sp, #64]
    ldp  x10, x11, [sp, #80]
    ldp  x12, x13, [sp, #96]
    ldp  x14, x15, [sp, #112]
    ldp  x17, x18, [sp, #128]
    ldp  x29, x30, [sp, #144]
    add  sp, sp, #304
    ret

    .balign 8
    .global nup_svc_stubs
nup_svc_stubs:
    .set svc_idx, 0
    .rept 0xC0
    svc  svc_idx
    ret
    .set svc_idx, svc_idx + 1
    .endr
