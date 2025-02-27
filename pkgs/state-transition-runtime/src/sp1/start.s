.section .text._start
.globl _start

_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    lla sp, STACK_TOP
    call __start
