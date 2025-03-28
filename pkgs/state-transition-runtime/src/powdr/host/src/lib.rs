use powdr::Session;

#[no_mangle]
pub extern "C" fn powdr_prove(
    serialized: *const u8,
    len: usize,
    output: *mut u8,
    output_len: usize,
) {
    let byte_slice = unsafe {
        if !serialized.is_null() {
            std::slice::from_raw_parts(serialized, len)
        } else {
            &[]
        }
    };

    let _output_slice = unsafe {
        if !serialized.is_null() {
            std::slice::from_raw_parts(output, len)
        } else {
            &[]
        }
    };

    let mut session = Session::builder()
        .guest_path("")
        .out_path("")
        .chunk_size_log2(18)
        .build()
        .write_bytes(byte_slice.to_vec());

    session.run();
    session.prove();
}
