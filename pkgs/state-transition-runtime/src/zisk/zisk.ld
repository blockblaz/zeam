OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
  rom   (xa) : ORIGIN = 0x80000000, LENGTH = 0x10000000
  ram   (wxa) : ORIGIN = 0xa0020000, LENGTH = 0x1FFE0000
}

PHDRS {
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  bss PT_LOAD FLAGS(6);
}

SECTIONS
{
  .text : { *(.text.init) *(.text .text.*)} >rom AT>rom :text

  . = ALIGN(8);
  PROVIDE(_global_pointer = .);
  .rodata : { *(.rodata .rodata.*)} >rom AT>rom :rodata

  . = 0xa0020000;
  .data : { *(.data .data.* .sdata .sdata.*) } >ram AT>ram :data

  .bss : {
    PROVIDE(_bss_start = .);
    *(.bss .bss.*);
    PROVIDE(_bss_end = .); # ... and one at the end
  } >ram AT>ram :bss

  . = ALIGN(8);
  PROVIDE(_init_stack_top = . + 0x100000); # reserve 1M bytes for the initialization stack

  PROVIDE(_kernel_heap_bottom = _init_stack_top);
  PROVIDE(_kernel_heap_top = ORIGIN(ram) + LENGTH(ram));
  PROVIDE(_kernel_heap_size = _kernel_heap_top - _kernel_heap_bottom);

  _end = .;
}
