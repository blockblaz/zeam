use std::fs;
use std::path::Path;

use bincode::Options;
use openvm_circuit::arch::ContinuationVmProof;
use openvm_platform::platform::memory::MEM_SIZE;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn, SC,
};
use openvm_stark_sdk::config::FriParameters;
use openvm_transpiler::elf::Elf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

// Maximum allowed sizes to prevent OOM from untrusted input
const MAX_INPUT_LEN: usize = 16 * 1024 * 1024; // 16 MB for serialized block input
const MAX_OUTPUT_LEN: usize = 256 * 1024 * 1024; // 256 MB for proof output buffer
const MAX_PATH_LEN: usize = 4096; // PATH_MAX on Linux
const MAX_RECEIPT_LEN: usize = 256 * 1024 * 1024; // 256 MB for proof receipt
const MAX_ELF_SIZE: u64 = 256 * 1024 * 1024; // 256 MB for ELF binary on disk

/// Build the canonical VM configuration shared by prover and verifier.
fn canonical_vm_config() -> SdkVmConfig {
    SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build()
}

/// Build the canonical FRI parameters shared by prover and verifier.
fn canonical_fri_params() -> FriParameters {
    FriParameters::standard_with_100_bits_conjectured_security(APP_LOG_BLOWUP)
}

// Canonical application log blowup factor used by both prover and verifier
const APP_LOG_BLOWUP: usize = 2;

// Structure to hold proof data for verification
#[derive(Serialize, Deserialize)]
struct OpenVMProofPackage {
    // We store the raw bytes since the actual types are complex with generics
    proof_bytes: Vec<u8>,
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

    if len > MAX_INPUT_LEN {
        panic!("Input length {} exceeds maximum {}", len, MAX_INPUT_LEN);
    }
    if output_len > MAX_OUTPUT_LEN {
        panic!(
            "Output length {} exceeds maximum {}",
            output_len, MAX_OUTPUT_LEN
        );
    }
    if binary_path_len > MAX_PATH_LEN {
        panic!(
            "Binary path length {} exceeds maximum {}",
            binary_path_len, MAX_PATH_LEN
        );
    }
    if result_path_len > MAX_PATH_LEN {
        panic!(
            "Result path length {} exceeds maximum {}",
            result_path_len, MAX_PATH_LEN
        );
    }

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

    let vm_config = canonical_vm_config();
    let sdk = Sdk::new();

    let elf_metadata = fs::metadata(binary_path).unwrap();
    if elf_metadata.len() > MAX_ELF_SIZE {
        panic!(
            "ELF binary size {} exceeds maximum {}",
            elf_metadata.len(),
            MAX_ELF_SIZE
        );
    }
    let elf_bytes = fs::read(binary_path).unwrap();

    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32).unwrap();

    let exe = sdk.transpile(elf, vm_config.transpiler()).unwrap();

    let mut stdin = StdIn::default();
    stdin.write(&serialized_block);

    let app_fri_params = canonical_fri_params();
    let app_config = AppConfig::new(app_fri_params, vm_config);

    let app_committed_exe = sdk.commit_app_exe(app_fri_params, exe).unwrap();

    let app_pk = Arc::new(sdk.app_keygen(app_config).unwrap());

    let proof = sdk
        .generate_app_proof(app_pk.clone(), app_committed_exe.clone(), stdin.clone())
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let elf_hash = hasher.finalize().to_vec();

    let proof_package = OpenVMProofPackage {
        proof_bytes: bincode::serialize(&proof).unwrap(),
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
    binary_path: *const u8,
    binary_path_len: usize,
    receipt: *const u8,
    receipt_len: usize,
) -> bool {
    if binary_path_len > MAX_PATH_LEN {
        eprintln!(
            "openvm_verify: binary path length {} exceeds maximum {}",
            binary_path_len, MAX_PATH_LEN
        );
        return false;
    }
    if receipt_len > MAX_RECEIPT_LEN {
        eprintln!(
            "openvm_verify: receipt length {} exceeds maximum {}",
            receipt_len, MAX_RECEIPT_LEN
        );
        return false;
    }

    let binary_path_slice = unsafe {
        if !binary_path.is_null() {
            std::slice::from_raw_parts(binary_path, binary_path_len)
        } else {
            eprintln!("openvm_verify: binary_path is null");
            return false;
        }
    };

    let receipt_slice = unsafe {
        if !receipt.is_null() {
            std::slice::from_raw_parts(receipt, receipt_len)
        } else {
            eprintln!("openvm_verify: receipt is null");
            return false;
        }
    };

    let binary_path = match std::str::from_utf8(binary_path_slice) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("openvm_verify: invalid binary path: {}", e);
            return false;
        }
    };

    // Deserialize the proof package with a size limit to prevent allocation bombs
    // from crafted length prefixes in the serialized data.
    let proof_package: OpenVMProofPackage = match bincode::DefaultOptions::new()
        .with_limit(MAX_RECEIPT_LEN as u64)
        .deserialize(receipt_slice)
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("openvm_verify: failed to deserialize proof package: {}", e);
            return false;
        }
    };

    // Verify ELF hash: read the binary ELF and check it matches the hash in the proof
    match fs::metadata(binary_path) {
        Ok(m) if m.len() > MAX_ELF_SIZE => {
            eprintln!(
                "openvm_verify: ELF binary size {} exceeds maximum {}",
                m.len(),
                MAX_ELF_SIZE
            );
            return false;
        }
        Err(e) => {
            eprintln!(
                "openvm_verify: failed to stat ELF at {}: {}",
                binary_path, e
            );
            return false;
        }
        _ => {}
    }
    let elf_bytes = match fs::read(binary_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "openvm_verify: failed to read ELF at {}: {}",
                binary_path, e
            );
            return false;
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let computed_hash = hasher.finalize().to_vec();

    if computed_hash != proof_package.elf_hash {
        eprintln!("openvm_verify: ELF hash mismatch — proof was generated for a different binary");
        return false;
    }

    // Deserialize the continuation VM proof
    let proof: ContinuationVmProof<SC> = match bincode::deserialize(&proof_package.proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("openvm_verify: failed to deserialize proof: {}", e);
            return false;
        }
    };

    // Independently derive the verifying key from canonical parameters.
    // This ensures the verifier never trusts a VK supplied by the prover.
    let vm_config = canonical_vm_config();
    let app_fri_params = canonical_fri_params();
    let app_config = AppConfig::new(app_fri_params, vm_config);

    let sdk = Sdk::new();
    let app_pk = match sdk.app_keygen(app_config) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("openvm_verify: failed to derive app proving key: {}", e);
            return false;
        }
    };
    let app_vk = app_pk.get_app_vk();

    // Verify the proof using the independently derived VK
    match sdk.verify_app_proof(&app_vk, &proof) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("openvm_verify: proof verification failed: {}", e);
            false
        }
    }
}
