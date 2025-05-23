use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, Receipt};
use std::fs;

#[no_mangle]
extern "C" fn risc0_prove(
    serialized_block: *const u8,
    len: usize,
    binary_path: *const u8,
    binary_path_len: usize,
    output: *mut u8,
    output_len: usize,
) -> u32 {
    let serialized_block = unsafe {
        if !serialized_block.is_null() {
            std::slice::from_raw_parts(serialized_block, len)
        } else {
            &[]
        }
    };
    let binary_path = unsafe {
        if !binary_path.is_null() {
            std::slice::from_raw_parts(binary_path, binary_path_len)
        } else {
            &[]
        }
    };
    let output: &mut [u8] = unsafe {
        if !output.is_null() {
            std::slice::from_raw_parts_mut(output, output_len)
        } else {
            panic!("null output");
        }
    };

    let guest_elf = fs::read(std::str::from_utf8(binary_path).unwrap()).unwrap();

    let env = ExecutorEnv::builder()
        .write_slice(serialized_block)
        .build()
        .unwrap();

    let prover = default_prover();
    let prove_info = prover.prove(env, &guest_elf).unwrap();
    let receipt = prove_info.receipt;
    let serialized_receipt = serde_cbor::to_vec(&receipt).unwrap();
    output[..serialized_receipt.len()].copy_from_slice(&serialized_receipt[..]);
    serialized_receipt.len() as u32
}

#[no_mangle]
extern "C" fn risc0_verify(
    binary_path: *const u8,
    binary_path_len: usize,
    receipt: *const u8,
    receipt_len: usize,
) -> bool {
    let binary_path = unsafe {
        if !binary_path.is_null() {
            std::slice::from_raw_parts(binary_path, binary_path_len)
        } else {
            &[]
        }
    };
    let receipt = unsafe {
        if !receipt.is_null() {
            std::slice::from_raw_parts(receipt, receipt_len)
        } else {
            &[]
        }
    };
    let receipt: Receipt = serde_cbor::from_slice(receipt).unwrap();

    let guest_elf = fs::read(std::str::from_utf8(binary_path).unwrap()).unwrap();
    let guest_id = compute_image_id(&guest_elf).unwrap();

    receipt.verify(guest_id).is_ok()
}
