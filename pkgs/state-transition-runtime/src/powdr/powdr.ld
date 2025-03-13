# Powdr linker script.
#
# This linker script provides usable definitions to these
# symbols, with a 256 MB stack.

PHDRS {
  # The powdr specific p_type 0x600000da indicates to
  # powdr ELF parser where the prover data is.
  powdr_prover_data_seg 0x600000da;

  # text is R (4) + X (1)
  text_seg PT_LOAD FLAGS(5);

  # data and bss segments are R (4) + W (2)
  # there is no point in having a separated rodata segment because powdr doesn't enforce permissions
  data_seg PT_LOAD FLAGS(6);
  bss_seg PT_LOAD FLAGS(6);
}

SECTIONS
{
  # Data starts here, before is the stack.
  . = 0x10000000;
  .powdr.prover.data (NOLOAD) : {
    PROVIDE( __powdr_prover_data_start = . );
    . += 0x10000000;
    PROVIDE( __powdr_prover_data_end = . );
  } :powdr_prover_data_seg

  . = ALIGN(0x1000); # Page-align BSS section
  PROVIDE(__global_pointer$ = .);

  # Text addresses are fake in powdr, we use a different address space.
  .text : ALIGN(4) { *(.text) } :text_seg

  .bss : { *(.sbss .bss .bss.*) } :bss_seg

  .rodata : ALIGN(4) {
    PROVIDE( __global_pointer$ = . + 0x800 );
    *(.rodata .rodata.* )
  } :data_seg

  .data : {
    *(.data .data.* )
  } :data_seg

  __powdr_stack_start = 0x10000000;
}

ASSERT(DEFINED(_start), "Error: _start is not defined.")
ENTRY(_start)
