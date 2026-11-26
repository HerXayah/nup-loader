// SPDX-License-Identifier: MIT
// Static 2048-slot AArch64 PLT tail-call trampoline table for Trace Launch mode.
// Preserves x0-x9, q0-q7, x29, x30, and sp bit-for-bit, then tail-calls the
// real target with `br x17` (standard AArch64 PLT ABI: PAC + BTI + varargs safe).

    .text
    .align 4

    .global nup_trace_common
    .type   nup_trace_common, %function
nup_trace_common:
    // Frame size: 240 bytes (16-byte aligned)
    //   [sp, #0x00] x29, x30
    //   [sp, #0x10] x0,  x1
    //   [sp, #0x20] x2,  x3
    //   [sp, #0x30] x4,  x5
    //   [sp, #0x40] x6,  x7
    //   [sp, #0x50] x8,  x9
    //   [sp, #0x60] q0,  q1
    //   [sp, #0x80] q2,  q3
    //   [sp, #0xa0] q4,  q5
    //   [sp, #0xc0] q6,  q7
    //   [sp, #0xe0] (16 bytes spare)
    sub     sp, sp, #240
    stp     x29, x30, [sp, #0x00]
    stp     x0,  x1,  [sp, #0x10]
    stp     x2,  x3,  [sp, #0x20]
    stp     x4,  x5,  [sp, #0x30]
    stp     x6,  x7,  [sp, #0x40]
    stp     x8,  x9,  [sp, #0x50]
    stp     q0,  q1,  [sp, #0x60]
    stp     q2,  q3,  [sp, #0x80]
    stp     q4,  q5,  [sp, #0xa0]
    stp     q6,  q7,  [sp, #0xc0]

    // nupTraceRecord(w0=slot_idx, x1=lr, x2=orig_x0, x3=orig_x1, x4=orig_x2, x5=orig_x3)
    mov     x5, x3
    mov     x4, x2
    mov     x3, x1
    mov     x2, x0
    mov     x1, x30
    mov     w0, w16
    bl      nupTraceRecord
    mov     x17, x0

    ldp     q6,  q7,  [sp, #0xc0]
    ldp     q4,  q5,  [sp, #0xa0]
    ldp     q2,  q3,  [sp, #0x80]
    ldp     q0,  q1,  [sp, #0x60]
    ldp     x8,  x9,  [sp, #0x50]
    ldp     x6,  x7,  [sp, #0x40]
    ldp     x4,  x5,  [sp, #0x30]
    ldp     x2,  x3,  [sp, #0x20]
    ldp     x0,  x1,  [sp, #0x10]
    ldp     x29, x30, [sp, #0x00]
    add     sp, sp, #240
    br      x17
    .size   nup_trace_common, .-nup_trace_common

    .macro TRAMP_1 idx
    movz    x16, #\idx
    b       nup_trace_common
    .endm

    .macro TRAMP_8 base
    TRAMP_1 (\base + 0)
    TRAMP_1 (\base + 1)
    TRAMP_1 (\base + 2)
    TRAMP_1 (\base + 3)
    TRAMP_1 (\base + 4)
    TRAMP_1 (\base + 5)
    TRAMP_1 (\base + 6)
    TRAMP_1 (\base + 7)
    .endm

    .macro TRAMP_64 base
    TRAMP_8 (\base + 0)
    TRAMP_8 (\base + 8)
    TRAMP_8 (\base + 16)
    TRAMP_8 (\base + 24)
    TRAMP_8 (\base + 32)
    TRAMP_8 (\base + 40)
    TRAMP_8 (\base + 48)
    TRAMP_8 (\base + 56)
    .endm

    .macro TRAMP_512 base
    TRAMP_64 (\base + 0)
    TRAMP_64 (\base + 64)
    TRAMP_64 (\base + 128)
    TRAMP_64 (\base + 192)
    TRAMP_64 (\base + 256)
    TRAMP_64 (\base + 320)
    TRAMP_64 (\base + 384)
    TRAMP_64 (\base + 448)
    .endm

    .align 3
    .global nup_trace_tramp_table
    .type   nup_trace_tramp_table, %function
nup_trace_tramp_table:
    TRAMP_512 0
    TRAMP_512 512
    TRAMP_512 1024
    TRAMP_512 1536
    .size   nup_trace_tramp_table, .-nup_trace_tramp_table
