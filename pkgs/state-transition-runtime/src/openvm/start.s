.section .text
.globl _start

_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, STACK_TOP
    call main
