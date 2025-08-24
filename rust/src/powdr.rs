use powdr::Session;
use std::path::Path;

#[no_mangle]
extern "C" fn powdr_prove(
    serialized: *const u8,
    len: usize,
    output: *mut u8,
    output_len: usize,
    binary_path: *const u8,
    binary_path_len: usize,
    result_path: *const u8,
    result_path_len: usize,
) {
    // This can only be initialized once during the
    // lifetime of the program. There is unfortunately
    // no way to check if it has already been initialized
    // and so we proceed.
    env_logger::try_init().unwrap_or(());

    println!(
        "Running the powdr transition prover, current dir={}",
        std::env::current_dir().unwrap().display()
    );
    let byte_slice = unsafe {
        if !serialized.is_null() {
            std::slice::from_raw_parts(serialized, len)
        } else {
            &[]
        }
    };

    let _output_slice = unsafe {
        if !output.is_null() {
            std::slice::from_raw_parts(output, output_len)
        } else {
            &[]
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

    let result_path = std::str::from_utf8(result_path_slice).unwrap();

    // Uncomment when debugging
    // println!("input={:?}", byte_slice);
    // println!(
    //     "binary path={}, result directory={}",
    //     binary_path, result_path
    // );

    let mut session = Session::builder()
        .guest_path(binary_path)
        .out_path(result_path)
        .chunk_size_log2(18)
        .build()
        .write_bytes(byte_slice.to_vec());

    // Uncomment when debugging
    // println!("dry run");
    session.run();

    // Uncomment when debugging
    // println!("proving starting");
    session.prove();
}
