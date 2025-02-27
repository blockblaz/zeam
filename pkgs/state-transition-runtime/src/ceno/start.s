.section .init
.global _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    la sp, _stack_start
    mv fp, sp

    call main
