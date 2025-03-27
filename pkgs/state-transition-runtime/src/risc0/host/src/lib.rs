use risc0_zkvm::{default_prover, ExecutorEnv};

#[no_mangle]
extern "C" fn prove(serialized_block: *const u8, len: usize) {
    let env = ExecutorEnv::builder()
        .write(&serialized_block)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let prove_info = prover
        .prove(env, "zeam-stf-risc0")
        .unwrap();
}

#[no_mangle]
extern "C" fn verify(receipt: ) -> bool {
    receipt.verify(zeam_id).unwrap();
}
