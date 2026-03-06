use std::fs;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkm_sdk::{ProverClient, ZKMProofWithPublicValues, ZKMStdin, ZKMVerifyingKey};

// Structure to hold proof data for verification
#[derive(Serialize, Deserialize)]
struct ZirenProofPackage {
    // Serialized ZKMProofWithPublicValues
    proof_bytes: Vec<u8>,
    // Serialized ZKMVerifyingKey
    vk_bytes: Vec<u8>,
    // SHA256 hash of the ELF binary, binding the proof to the guest program
    elf_hash: Vec<u8>,
}

#[no_mangle]
extern "C" fn ziren_prove(
    serialized: *const u8,
    len: usize,
    binary_path: *const u8,
    binary_path_len: usize,
    output: *mut u8,
    output_len: usize,
) -> u32 {
    println!(
        "Running the Ziren transition prover, current dir={}",
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

    let binary_path = std::str::from_utf8(binary_path_slice).unwrap();
    let elf_bytes = fs::read(binary_path).unwrap();

    let client = ProverClient::new();
    let (pk, vk) = client.setup(&elf_bytes);

    let mut stdin = ZKMStdin::new();
    // Write 4-byte length prefix followed by the actual data
    let len_bytes = (serialized_block.len() as u32).to_le_bytes();
    stdin.write_slice(&len_bytes);
    stdin.write_slice(serialized_block);

    let proof = client.prove(&pk, stdin).run().unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let elf_hash = hasher.finalize().to_vec();

    let proof_package = ZirenProofPackage {
        proof_bytes: bincode::serialize(&proof).unwrap(),
        vk_bytes: bincode::serialize(&vk).unwrap(),
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
extern "C" fn ziren_verify(
    binary_path: *const u8,
    binary_path_len: usize,
    receipt: *const u8,
    receipt_len: usize,
) -> bool {
    let binary_path_slice = unsafe {
        if !binary_path.is_null() {
            std::slice::from_raw_parts(binary_path, binary_path_len)
        } else {
            eprintln!("ziren_verify: binary_path is null");
            return false;
        }
    };

    let receipt_slice = unsafe {
        if !receipt.is_null() {
            std::slice::from_raw_parts(receipt, receipt_len)
        } else {
            eprintln!("ziren_verify: receipt is null");
            return false;
        }
    };

    let binary_path = match std::str::from_utf8(binary_path_slice) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ziren_verify: invalid binary path: {}", e);
            return false;
        }
    };

    // Deserialize the proof package from receipt bytes
    let proof_package: ZirenProofPackage = match bincode::deserialize(receipt_slice) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ziren_verify: failed to deserialize proof package: {}", e);
            return false;
        }
    };

    // Verify ELF hash: read the binary ELF and check it matches the hash in the proof
    let elf_bytes = match fs::read(binary_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "ziren_verify: failed to read ELF at {}: {}",
                binary_path, e
            );
            return false;
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let computed_hash = hasher.finalize().to_vec();

    if computed_hash != proof_package.elf_hash {
        eprintln!(
            "ziren_verify: ELF hash mismatch — proof was generated for a different binary"
        );
        return false;
    }

    // Deserialize the ZKM proof
    let proof: ZKMProofWithPublicValues = match bincode::deserialize(&proof_package.proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ziren_verify: failed to deserialize proof: {}", e);
            return false;
        }
    };

    // Deserialize the verifying key
    let vk: ZKMVerifyingKey = match bincode::deserialize(&proof_package.vk_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ziren_verify: failed to deserialize verifying key: {}", e);
            return false;
        }
    };

    // Verify the proof using the ZKM SDK
    let client = ProverClient::new();
    match client.verify(&proof, &vk) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("ziren_verify: proof verification failed: {}", e);
            false
        }
    }
}
