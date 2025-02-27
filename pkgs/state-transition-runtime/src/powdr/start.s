.global _start
.type _start, @function

_start:
    .option push
    .option norelax
    lla gp, __global_pointer$
    .option pop
    lla sp, __powdr_stack_start
    call main
