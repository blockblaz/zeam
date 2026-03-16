.section .text._start
.globl __start

__start:
    la $gp, _gp
    la $sp, _stack_top
    jal main
    nop
