use std::fs;
use std::path::Path;

use openvm_platform::platform::memory::MEM_SIZE;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::config::FriParameters;
use openvm_transpiler::elf::Elf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

// Structure to hold proof data for verification
#[derive(Serialize, Deserialize)]
struct OpenVMProofPackage {
    // We store the raw bytes since the actual types are complex with generics
    proof_bytes: Vec<u8>,
    // Store the verification key bytes for proof verification
    vk_bytes: Vec<u8>,
    // Store configuration parameters to reconstruct verification context
    app_log_blowup: usize,
    // Store a hash/commitment of the ELF for verification
    elf_hash: Vec<u8>,
}

#[no_mangle]
extern "C" fn openvm_prove(
    serialized: *const u8,
    len: usize,
    output: *mut u8,
    output_len: usize,
    binary_path: *const u8,
    binary_path_len: usize,
    result_path: *const u8,
    result_path_len: usize,
) -> u32 {
    println!(
        "Running the openvm transition prover, current dir={}",
        std::env::current_dir().unwrap().display()
    );
    let serialized_block = unsafe {
        if !serialized.is_null() {
            std::slice::from_raw_parts(serialized, len)
        } else {
            &[]
        }
    };

    let output_slice = unsafe {
        if !output.is_null() {
            std::slice::from_raw_parts_mut(output, output_len)
        } else {
            panic!("Output buffer is null")
        }
    };

    let binary_path_slice = unsafe {
        if !binary_path.is_null() {
            std::slice::from_raw_parts(binary_path, binary_path_len)
        } else {
            &[]
        }
    };

    let result_path_slice = unsafe {
        if !result_path.is_null() {
            std::slice::from_raw_parts(result_path, result_path_len)
        } else {
            &[]
        }
    };

    let binary_path = std::str::from_utf8(binary_path_slice).unwrap();
    let binary = Path::new(binary_path);
    if !binary.exists() {
        panic!("path does not exist");
    }

    let _result_path = std::str::from_utf8(result_path_slice).unwrap();

    // Uncomment when debugging
    // println!("input={:?}", byte_slice);
    // println!(
    //     "binary path={}, result directory={}",
    //     binary_path, result_path
    // );

    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build();
    let sdk = Sdk::new();

    let elf_bytes = fs::read(binary_path).unwrap();

    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32).unwrap();

    let exe = sdk.transpile(elf, vm_config.transpiler()).unwrap();

    let mut stdin = StdIn::default();
    stdin.write(&serialized_block);

    let app_log_blowup = 2;
    let app_fri_params = FriParameters::standard_with_100_bits_conjectured_security(app_log_blowup);
    let app_config = AppConfig::new(app_fri_params, vm_config);

    let app_committed_exe = sdk.commit_app_exe(app_fri_params, exe).unwrap();

    let app_pk = Arc::new(sdk.app_keygen(app_config).unwrap());

    let app_vk = app_pk.get_app_vk();

    let proof = sdk
        .generate_app_proof(app_pk.clone(), app_committed_exe.clone(), stdin.clone())
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let elf_hash = hasher.finalize().to_vec();

    let proof_package = OpenVMProofPackage {
        proof_bytes: bincode::serialize(&proof).unwrap(),
        vk_bytes: bincode::serialize(&app_vk).unwrap(),
        app_log_blowup,
        elf_hash,
    };

    let serialized_proof = bincode::serialize(&proof_package).unwrap();
    if serialized_proof.len() > output_len {
        panic!(
            "Proof size {} exceeds output buffer size {}",
            serialized_proof.len(),
            output_len
        );
    }

    output_slice[..serialized_proof.len()].copy_from_slice(&serialized_proof);
    serialized_proof.len() as u32
}

#[no_mangle]
extern "C" fn openvm_verify(
    _binary_path: *const u8,
    _binary_path_len: usize,
    _receipt: *const u8,
    _receipt_len: usize,
) -> bool {
    // TODO: Implement verification
    eprintln!("OpenVM verification not yet implemented");
    true
}
