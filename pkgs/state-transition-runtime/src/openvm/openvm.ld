OUTPUT_FORMAT("elf32-littleriscv", "elf32-littleriscv", "elf32-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  stack        : ORIGIN = 0x00000400, LENGTH =  0x001FFC00
  ram          : ORIGIN = 0x00200800, LENGTH =  0x1FDFF800
}

SECTIONS {
  . = 0x00200800;
  .text 0x00200800 : ALIGN(4) {
    KEEP (*(.init))
    . = ALIGN(4);
    *(.text*)
    . = ALIGN(4);
    *(.rodata*)
    . = ALIGN(4);
    *(.srodata*)
  } >ram

  . = ALIGN(4);

  .data : ALIGN(4) {
    *(.data .data.*)
    *(.gnu.linkonce.d.*)
    __global_pointer$ = . + 0x800;
    *(.sdata .sdata.* .sdata2.*)
    *(.gnu.linkonce.s.*)
  } >ram

  . = ALIGN(4);

  .bss (NOLOAD) : ALIGN(4) {
    __bss_start = .;
    *(.sbss*)
    *(.gnu.linkonce.sb.*)
    *(.bss .bss.*)
    *(.gnu.linkonce.b.*)
    *(COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } >ram

  PROVIDE(_heap_start = . );

  PROVIDE(STACK_TOP = 0x00200400);

  /DISCARD/ : {
    *(.rel*)
    *(.comment)
    *(.eh_frame)
    *(.riscv.attributes)
  }
}
