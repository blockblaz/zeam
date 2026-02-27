use std::fs;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

// Structure to hold proof data for verification
#[derive(Serialize, Deserialize)]
struct SP1ProofPackage {
    // Serialized SP1ProofWithPublicValues
    proof_bytes: Vec<u8>,
    // Serialized SP1VerifyingKey
    vk_bytes: Vec<u8>,
    // SHA256 hash of the ELF binary, binding the proof to the guest program
    elf_hash: Vec<u8>,
}

#[no_mangle]
extern "C" fn sp1_prove(
    serialized: *const u8,
    len: usize,
    binary_path: *const u8,
    binary_path_len: usize,
    output: *mut u8,
    output_len: usize,
) -> u32 {
    println!(
        "Running the SP1 transition prover, current dir={}",
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

    let mut stdin = SP1Stdin::new();
    // Write 4-byte length prefix followed by the actual data
    let len_bytes = (serialized_block.len() as u32).to_le_bytes();
    stdin.write_slice(&len_bytes);
    stdin.write_slice(serialized_block);

    let proof = client.prove(&pk, stdin).run().unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let elf_hash = hasher.finalize().to_vec();

    let proof_package = SP1ProofPackage {
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
extern "C" fn sp1_verify(
    binary_path: *const u8,
    binary_path_len: usize,
    receipt: *const u8,
    receipt_len: usize,
) -> bool {
    let binary_path_slice = unsafe {
        if !binary_path.is_null() {
            std::slice::from_raw_parts(binary_path, binary_path_len)
        } else {
            eprintln!("sp1_verify: binary_path is null");
            return false;
        }
    };

    let receipt_slice = unsafe {
        if !receipt.is_null() {
            std::slice::from_raw_parts(receipt, receipt_len)
        } else {
            eprintln!("sp1_verify: receipt is null");
            return false;
        }
    };

    let binary_path = match std::str::from_utf8(binary_path_slice) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sp1_verify: invalid binary path: {}", e);
            return false;
        }
    };

    // Deserialize the proof package from receipt bytes
    let proof_package: SP1ProofPackage = match bincode::deserialize(receipt_slice) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sp1_verify: failed to deserialize proof package: {}", e);
            return false;
        }
    };

    // Verify ELF hash: read the binary ELF and check it matches the hash in the proof
    let elf_bytes = match fs::read(binary_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sp1_verify: failed to read ELF at {}: {}", binary_path, e);
            return false;
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let computed_hash = hasher.finalize().to_vec();

    if computed_hash != proof_package.elf_hash {
        eprintln!(
            "sp1_verify: ELF hash mismatch — proof was generated for a different binary"
        );
        return false;
    }

    // Deserialize the SP1 proof
    let proof: SP1ProofWithPublicValues = match bincode::deserialize(&proof_package.proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sp1_verify: failed to deserialize proof: {}", e);
            return false;
        }
    };

    // Deserialize the verifying key
    let vk: SP1VerifyingKey = match bincode::deserialize(&proof_package.vk_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sp1_verify: failed to deserialize verifying key: {}", e);
            return false;
        }
    };

    // Verify the proof using the SP1 SDK
    let client = ProverClient::new();
    match client.verify(&proof, &vk) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("sp1_verify: proof verification failed: {}", e);
            false
        }
    }
}
