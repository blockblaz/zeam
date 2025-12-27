use leansig::{signature::SignatureScheme, MESSAGE_LENGTH};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use serde_json::Value;

pub type HashSigScheme =
    leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type HashSigPrivateKey = <HashSigScheme as SignatureScheme>::SecretKey;
pub type HashSigPublicKey = <HashSigScheme as SignatureScheme>::PublicKey;
pub type HashSigSignature = <HashSigScheme as SignatureScheme>::Signature;

#[repr(C)]
pub struct PrivateKey {
    inner: HashSigPrivateKey,
}

#[repr(C)]
pub struct PublicKey {
    pub inner: HashSigPublicKey,
}

#[repr(C)]
pub struct Signature {
    pub inner: HashSigSignature,
}

/// KeyPair structure for FFI - holds both public and private keys
#[repr(C)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Signing failed: {0:?}")]
    SigningFailed(leansig::signature::SigningError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("Verification failed")]
    VerificationFailed,
}

impl PrivateKey {
    pub fn new(inner: HashSigPrivateKey) -> Self {
        Self { inner }
    }

    pub fn generate<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (PublicKey, Self) {
        let (public_key, private_key) =
            <HashSigScheme as SignatureScheme>::key_gen(rng, activation_epoch, num_active_epochs);

        (PublicKey::new(public_key), Self::new(private_key))
    }

    pub fn sign(
        &self,
        message: &[u8; MESSAGE_LENGTH],
        epoch: u32,
    ) -> Result<Signature, SigningError> {
        Ok(Signature::new(
            <HashSigScheme as SignatureScheme>::sign(&self.inner, epoch, message)
                .map_err(SigningError::SigningFailed)?,
        ))
    }
}

impl PublicKey {
    pub fn new(inner: HashSigPublicKey) -> Self {
        Self { inner }
    }
}

impl Signature {
    pub fn new(inner: HashSigSignature) -> Self {
        Self { inner }
    }

    pub fn verify(
        &self,
        message: &[u8; MESSAGE_LENGTH],
        public_key: &PublicKey,
        epoch: u32,
    ) -> bool {
        <HashSigScheme as SignatureScheme>::verify(&public_key.inner, epoch, message, &self.inner)
    }
}

// FFI Functions for Zig interop

/// Generate a new key pair
/// Returns a pointer to the KeyPair or null on error
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
#[no_mangle]
pub unsafe extern "C" fn hashsig_keypair_generate(
    seed_phrase: *const c_char,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut KeyPair {
    let seed_phrase = unsafe { CStr::from_ptr(seed_phrase).to_string_lossy().into_owned() };

    // Hash the seed phrase to get a 32-byte seed
    let mut hasher = Sha256::new();
    hasher.update(seed_phrase.as_bytes());
    let seed = hasher.finalize().into();

    let (public_key, private_key) = PrivateKey::generate(
        &mut <ChaCha20Rng as SeedableRng>::from_seed(seed),
        activation_epoch,
        num_active_epochs,
    );

    let keypair = Box::new(KeyPair {
        public_key,
        private_key,
    });

    Box::into_raw(keypair)
}

/// Reconstruct a key pair from SSZ-encoded secret and public keys
/// Returns a pointer to the KeyPair or null on error
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
#[no_mangle]
pub unsafe extern "C" fn hashsig_keypair_from_ssz(
    private_key_ptr: *const u8,
    private_key_len: usize,
    public_key_ptr: *const u8,
    public_key_len: usize,
) -> *mut KeyPair {
    if private_key_ptr.is_null() || public_key_ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let sk_slice = slice::from_raw_parts(private_key_ptr, private_key_len);
        let pk_slice = slice::from_raw_parts(public_key_ptr, public_key_len);

        let private_key: HashSigPrivateKey = match HashSigPrivateKey::from_ssz_bytes(sk_slice) {
            Ok(key) => key,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        let public_key: HashSigPublicKey = match HashSigPublicKey::from_ssz_bytes(pk_slice) {
            Ok(key) => key,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        let keypair = Box::new(KeyPair {
            public_key: PublicKey::new(public_key),
            private_key: PrivateKey::new(private_key),
        });

        Box::into_raw(keypair)
    }
}

/// Free a key pair
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
#[no_mangle]
pub unsafe extern "C" fn hashsig_keypair_free(keypair: *mut KeyPair) {
    if !keypair.is_null() {
        unsafe {
            let _ = Box::from_raw(keypair);
        }
    }
}

/// Get a pointer to the public key from a keypair
/// Returns a pointer to the embedded PublicKey or null if keypair is null
/// Note: The returned pointer is only valid as long as the KeyPair is alive
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
/// The caller must ensure that the keypair pointer is valid or null
#[no_mangle]
pub unsafe extern "C" fn hashsig_keypair_get_public_key(
    keypair: *const KeyPair,
) -> *const PublicKey {
    if keypair.is_null() {
        return ptr::null();
    }
    &(*keypair).public_key
}

/// Get a pointer to the private key from a keypair
/// Returns a pointer to the embedded PrivateKey or null if keypair is null
/// Note: The returned pointer is only valid as long as the KeyPair is alive
/// # Safety
/// This is meant to be called from zig, so the pointers will always dereference correctly
/// The caller must ensure that the keypair pointer is valid or null
#[no_mangle]
pub unsafe extern "C" fn hashsig_keypair_get_private_key(
    keypair: *const KeyPair,
) -> *const PrivateKey {
    if keypair.is_null() {
        return ptr::null();
    }
    &(*keypair).private_key
}

/// Construct a standalone public key from SSZ-encoded bytes.
/// Returns a pointer to PublicKey or null on error.
/// # Safety
/// Inputs must be valid pointers and buffers.
#[no_mangle]
pub unsafe extern "C" fn hashsig_public_key_from_ssz(
    public_key_ptr: *const u8,
    public_key_len: usize,
) -> *mut PublicKey {
    if public_key_ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let pk_slice = slice::from_raw_parts(public_key_ptr, public_key_len);
        let public_key: HashSigPublicKey = match HashSigPublicKey::from_ssz_bytes(pk_slice) {
            Ok(key) => key,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        Box::into_raw(Box::new(PublicKey::new(public_key)))
    }
}

/// Free a public key created via hashsig_public_key_from_ssz.
/// # Safety
/// Pointer must be valid or null.
#[no_mangle]
pub unsafe extern "C" fn hashsig_public_key_free(public_key: *mut PublicKey) {
    if !public_key.is_null() {
        unsafe {
            let _ = Box::from_raw(public_key);
        }
    }
}

/// Sign a message using a private key directly
/// Returns pointer to Signature on success, null on error
/// # Safety
/// This is meant to be called from zig, so it's safe as the pointer will always exist
#[no_mangle]
pub unsafe extern "C" fn hashsig_sign(
    private_key: *const PrivateKey,
    message_ptr: *const u8,
    epoch: u32,
) -> *mut Signature {
    if private_key.is_null() || message_ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let private_key_ref = &*private_key;
        let message_slice = slice::from_raw_parts(message_ptr, MESSAGE_LENGTH);

        // Convert slice to array
        let message_array: &[u8; MESSAGE_LENGTH] = match message_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        let signature = match private_key_ref.sign(message_array, epoch) {
            Ok(sig) => sig,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        Box::into_raw(Box::new(signature))
    }
}

/// Free a signature
/// # Safety
/// This is meant to be called from zig, so it's safe as the pointer will always exist
#[no_mangle]
pub unsafe extern "C" fn hashsig_signature_free(signature: *mut Signature) {
    if !signature.is_null() {
        unsafe {
            let _ = Box::from_raw(signature);
        }
    }
}

/// Construct a signature from SSZ-encoded bytes.
/// Returns a pointer to Signature or null on error.
/// # Safety
/// Inputs must be valid pointers and buffers.
#[no_mangle]
pub unsafe extern "C" fn hashsig_signature_from_ssz(
    signature_ptr: *const u8,
    signature_len: usize,
) -> *mut Signature {
    if signature_ptr.is_null() || signature_len == 0 {
        return ptr::null_mut();
    }

    unsafe {
        let sig_slice = slice::from_raw_parts(signature_ptr, signature_len);
        let signature: HashSigSignature = match HashSigSignature::from_ssz_bytes(sig_slice) {
            Ok(sig) => sig,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        Box::into_raw(Box::new(Signature { inner: signature }))
    }
}

/// Verify a signature using a public key directly
/// Returns 1 if valid, 0 if invalid, -1 on error
/// # Safety
/// This is meant to be called from zig, so it's safe as the pointer will always exist
#[no_mangle]
pub unsafe extern "C" fn hashsig_verify(
    public_key: *const PublicKey,
    message_ptr: *const u8,
    epoch: u32,
    signature: *const Signature,
) -> i32 {
    if public_key.is_null() || message_ptr.is_null() || signature.is_null() {
        return -1;
    }

    unsafe {
        let public_key_ref = &*public_key;
        let signature_ref = &*signature;
        let message_slice = slice::from_raw_parts(message_ptr, MESSAGE_LENGTH);

        // Convert slice to array
        let message_array: &[u8; MESSAGE_LENGTH] = match message_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return -1;
            }
        };

        match signature_ref.verify(message_array, public_key_ref, epoch) {
            true => 1,
            false => 0,
        }
    }
}

/// Get the message length constant
/// # Safety
/// This is meant to be called from zig, so it's safe as the pointer will always exist
#[no_mangle]
pub extern "C" fn hashsig_message_length() -> usize {
    MESSAGE_LENGTH
}

use ssz::{Decode, Encode};

/// Serialize a signature to bytes using SSZ encoding
/// Returns number of bytes written, or 0 on error
/// # Safety
/// buffer must point to a valid buffer of sufficient size (recommend 4000+ bytes)
#[no_mangle]
pub unsafe extern "C" fn hashsig_signature_to_bytes(
    signature: *const Signature,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if signature.is_null() || buffer.is_null() {
        return 0;
    }

    unsafe {
        let sig_ref = &*signature;

        // Directly SSZ encode the signature (leansig has SSZ support built-in)
        let ssz_bytes = sig_ref.inner.as_ssz_bytes();

        if ssz_bytes.len() > buffer_len {
            return 0;
        }

        let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);
        output_slice[..ssz_bytes.len()].copy_from_slice(&ssz_bytes);
        ssz_bytes.len()
    }
}

/// Serialize a public key pointer to bytes using SSZ encoding
/// Returns number of bytes written, or 0 on error
/// # Safety
/// buffer must point to a valid buffer of sufficient size
#[no_mangle]
pub unsafe extern "C" fn hashsig_public_key_to_bytes(
    public_key: *const PublicKey,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if public_key.is_null() || buffer.is_null() {
        return 0;
    }

    unsafe {
        let public_key_ref = &*public_key;

        // Directly SSZ encode the public key (leansig has SSZ support built-in)
        let ssz_bytes = public_key_ref.inner.as_ssz_bytes();

        if ssz_bytes.len() > buffer_len {
            return 0;
        }

        let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);
        output_slice[..ssz_bytes.len()].copy_from_slice(&ssz_bytes);
        ssz_bytes.len()
    }
}

/// Serialize a private key pointer to bytes using SSZ encoding
/// Returns number of bytes written, or 0 on error
/// # Safety
/// buffer must point to a valid buffer of sufficient size
#[no_mangle]
pub unsafe extern "C" fn hashsig_private_key_to_bytes(
    private_key: *const PrivateKey,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if private_key.is_null() || buffer.is_null() {
        return 0;
    }

    unsafe {
        let private_key_ref = &*private_key;

        // Directly SSZ encode the private key (leansig has SSZ support built-in)
        let ssz_bytes = private_key_ref.inner.as_ssz_bytes();

        if ssz_bytes.len() > buffer_len {
            return 0;
        }

        let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);
        output_slice[..ssz_bytes.len()].copy_from_slice(&ssz_bytes);
        ssz_bytes.len()
    }
}

/// Verify XMSS signature from SSZ-encoded bytes
/// Returns 1 if valid, 0 if invalid, -1 on error
/// # Safety
/// All pointers must be valid and point to correctly sized data
#[no_mangle]
pub unsafe extern "C" fn hashsig_verify_ssz(
    pubkey_bytes: *const u8,
    pubkey_len: usize,
    message: *const u8,
    epoch: u32,
    signature_bytes: *const u8,
    signature_len: usize,
) -> i32 {
    if pubkey_bytes.is_null() || message.is_null() || signature_bytes.is_null() {
        return -1;
    }

    unsafe {
        let pk_data = slice::from_raw_parts(pubkey_bytes, pubkey_len);
        let sig_data = slice::from_raw_parts(signature_bytes, signature_len);
        let msg_data = slice::from_raw_parts(message, MESSAGE_LENGTH);

        let message_array: &[u8; MESSAGE_LENGTH] = match msg_data.try_into() {
            Ok(arr) => arr,
            Err(_) => return -1,
        };

        // Debug: print first 36 bytes of signature
        eprintln!("[hashsig_verify_ssz] pubkey_len={}, sig_len={}, epoch={}", pubkey_len, signature_len, epoch);
        eprintln!("[hashsig_verify_ssz] sig first 36 bytes: {:02x?}", &sig_data[..36.min(sig_data.len())]);
        eprintln!("[hashsig_verify_ssz] message: {:02x?}", message_array);

        let mut hasher = Sha256::new();
        hasher.update(pk_data);
        let pk_sha256 = hasher.finalize_reset();
        hasher.update(sig_data);
        let sig_sha256 = hasher.finalize();
        eprintln!("[hashsig_verify_ssz] pubkey sha256: {:02x}", pk_sha256);
        eprintln!("[hashsig_verify_ssz] signature sha256: {:02x}", sig_sha256);

        // Directly SSZ decode (leansig has SSZ support built-in)
        let pk: HashSigPublicKey = match HashSigPublicKey::from_ssz_bytes(pk_data) {
            Ok(pk) => pk,
            Err(e) => {
                eprintln!("[hashsig_verify_ssz] pubkey decode error: {:?}", e);
                return -1;
            }
        };

        let sig: HashSigSignature = match HashSigSignature::from_ssz_bytes(sig_data) {
            Ok(sig) => sig,
            Err(e) => {
                eprintln!("[hashsig_verify_ssz] signature decode error: {:?}", e);
                return -1;
            }
        };

        // SSZ round-trip checks: if these fail, the input bytes are not what leansig
        // would produce for the decoded structures (often indicates a layout mismatch).
        let pk_roundtrip = pk.as_ssz_bytes();
        if pk_roundtrip.as_slice() != pk_data {
            let min_len = pk_roundtrip.len().min(pk_data.len());
            let mut mismatch_at: Option<usize> = None;
            for i in 0..min_len {
                if pk_roundtrip[i] != pk_data[i] {
                    mismatch_at = Some(i);
                    break;
                }
            }
            eprintln!(
                "[hashsig_verify_ssz] pubkey SSZ roundtrip mismatch: in_len={}, out_len={}, first_mismatch={:?}",
                pk_data.len(),
                pk_roundtrip.len(),
                mismatch_at
            );
        }

        let sig_roundtrip = sig.as_ssz_bytes();
        if sig_roundtrip.as_slice() != sig_data {
            let min_len = sig_roundtrip.len().min(sig_data.len());
            let mut mismatch_at: Option<usize> = None;
            for i in 0..min_len {
                if sig_roundtrip[i] != sig_data[i] {
                    mismatch_at = Some(i);
                    break;
                }
            }
            eprintln!(
                "[hashsig_verify_ssz] signature SSZ roundtrip mismatch: in_len={}, out_len={}, first_mismatch={:?}",
                sig_data.len(),
                sig_roundtrip.len(),
                mismatch_at
            );
        }

        // Debug: verify SSZ roundtrips. If this fails, we're not verifying the same
        // structured data that Python/Zig expect.
        let pk_roundtrip = pk.as_ssz_bytes();
        if pk_roundtrip != pk_data {
            let mut hasher = Sha256::new();
            hasher.update(pk_data);
            let pk_in_hash = hasher.finalize_reset();
            hasher.update(&pk_roundtrip);
            let pk_rt_hash = hasher.finalize();

            let mismatch_idx = pk_data
                .iter()
                .zip(pk_roundtrip.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(0);

            eprintln!(
                "[hashsig_verify_ssz] pubkey SSZ roundtrip mismatch: in_len={}, rt_len={}, first_mismatch_at={}, in_sha256={:02x}, rt_sha256={:02x}",
                pk_data.len(),
                pk_roundtrip.len(),
                mismatch_idx,
                pk_in_hash,
                pk_rt_hash
            );
        } else {
            eprintln!("[hashsig_verify_ssz] pubkey SSZ roundtrip OK");
        }

        let sig_roundtrip = sig.as_ssz_bytes();
        if sig_roundtrip != sig_data {
            let mut hasher = Sha256::new();
            hasher.update(sig_data);
            let sig_in_hash = hasher.finalize_reset();
            hasher.update(&sig_roundtrip);
            let sig_rt_hash = hasher.finalize();

            let mismatch_idx = sig_data
                .iter()
                .zip(sig_roundtrip.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(0);

            eprintln!(
                "[hashsig_verify_ssz] signature SSZ roundtrip mismatch: in_len={}, rt_len={}, first_mismatch_at={}, in_sha256={:02x}, rt_sha256={:02x}",
                sig_data.len(),
                sig_roundtrip.len(),
                mismatch_idx,
                sig_in_hash,
                sig_rt_hash
            );
        } else {
            eprintln!("[hashsig_verify_ssz] signature SSZ roundtrip OK");
        }

        let is_valid = <HashSigScheme as SignatureScheme>::verify(&pk, epoch, message_array, &sig);
        eprintln!("[hashsig_verify_ssz] verify result: {}", is_valid);

        if is_valid {
            1
        } else {
            0
        }
    }
}

fn json_u32(value: &Value) -> Option<u32> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        _ => None,
    }
}

fn json_get<'a>(obj: &'a Value, key: &str) -> Option<&'a Value> {
    match obj {
        Value::Object(map) => map.get(key),
        _ => None,
    }
}

fn parse_u32_fixed_array(value: &Value, expected_len: usize) -> Option<Vec<u32>> {
    let arr = match value {
        Value::Array(a) => a,
        _ => return None,
    };
    if arr.len() != expected_len {
        return None;
    }
    let mut out = Vec::with_capacity(expected_len);
    for v in arr {
        out.push(json_u32(v)?);
    }
    Some(out)
}

fn parse_vec_of_u32x8(value: &Value) -> Option<Vec<[u32; 8]>> {
    let arr = match value {
        Value::Array(a) => a,
        _ => return None,
    };

    let mut out: Vec<[u32; 8]> = Vec::with_capacity(arr.len());
    for item in arr {
        let data = json_get(item, "data")?;
        let nums = parse_u32_fixed_array(data, 8)?;
        let mut fixed = [0u32; 8];
        fixed.copy_from_slice(&nums);
        out.push(fixed);
    }
    Some(out)
}

fn write_u32_le(dst: &mut [u8], offset: usize, v: u32) -> Option<()> {
    let end = offset.checked_add(4)?;
    dst.get_mut(offset..end)?.copy_from_slice(&v.to_le_bytes());
    Some(())
}

/// Convert a signature JSON object into SSZ-encoded signature bytes.
///
/// Expected JSON shape (object):
/// { "path": {"siblings": {"data": [ {"data": [u32;8]}, ... ]}},
///   "rho": {"data": [u32;7]},
///   "hashes": {"data": [ {"data": [u32;8]}, ... ]} }
///
/// Returns number of bytes written, or 0 on error.
#[no_mangle]
pub unsafe extern "C" fn hashsig_signature_ssz_from_json(
    signature_json_ptr: *const u8,
    signature_json_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> usize {
    if signature_json_ptr.is_null() || out_ptr.is_null() {
        return 0;
    }

    let json_bytes = unsafe { slice::from_raw_parts(signature_json_ptr, signature_json_len) };
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, out_len) };

    let sig_val: Value = match serde_json::from_slice(json_bytes) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // Extract siblings
    let path = match json_get(&sig_val, "path") {
        Some(v) => v,
        None => return 0,
    };
    let siblings = match json_get(path, "siblings").and_then(|v| json_get(v, "data")) {
        Some(v) => v,
        None => return 0,
    };
    let siblings_vec = match parse_vec_of_u32x8(siblings) {
        Some(v) => v,
        None => return 0,
    };

    // Extract rho
    let rho = match json_get(&sig_val, "rho").and_then(|v| json_get(v, "data")) {
        Some(v) => v,
        None => return 0,
    };
    let rho_vec = match parse_u32_fixed_array(rho, 7) {
        Some(v) => v,
        None => return 0,
    };

    // Extract hashes
    let hashes = match json_get(&sig_val, "hashes").and_then(|v| json_get(v, "data")) {
        Some(v) => v,
        None => return 0,
    };
    let hashes_vec = match parse_vec_of_u32x8(hashes) {
        Some(v) => v,
        None => return 0,
    };

    let sibling_size: usize = 8 * 4;
    let hash_size: usize = 8 * 4;
    let path_fixed_part: usize = 4;
    let sig_fixed_part: usize = 36;

    let path_variable_size = siblings_vec.len().checked_mul(sibling_size).unwrap_or(usize::MAX);
    if path_variable_size == usize::MAX {
        return 0;
    }
    let path_total_size = match path_fixed_part.checked_add(path_variable_size) {
        Some(v) => v,
        None => return 0,
    };

    let hashes_size = hashes_vec.len().checked_mul(hash_size).unwrap_or(usize::MAX);
    if hashes_size == usize::MAX {
        return 0;
    }

    let total_size = match sig_fixed_part.checked_add(path_total_size).and_then(|v| v.checked_add(hashes_size)) {
        Some(v) => v,
        None => return 0,
    };

    if total_size > out_len {
        return 0;
    }
    out[..total_size].fill(0);

    let offset_path: u32 = match u32::try_from(sig_fixed_part) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let offset_hashes_u = match sig_fixed_part.checked_add(path_total_size) {
        Some(v) => v,
        None => return 0,
    };
    let offset_hashes: u32 = match u32::try_from(offset_hashes_u) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // Signature fixed part
    let mut write_pos: usize = 0;
    if write_u32_le(out, write_pos, offset_path).is_none() {
        return 0;
    }
    write_pos += 4;
    for v in rho_vec {
        if write_u32_le(out, write_pos, v).is_none() {
            return 0;
        }
        write_pos += 4;
    }
    if write_u32_le(out, write_pos, offset_hashes).is_none() {
        return 0;
    }
    write_pos += 4;

    // Path (HashTreeOpening)
    let path_siblings_offset: u32 = 4;
    if write_u32_le(out, write_pos, path_siblings_offset).is_none() {
        return 0;
    }
    write_pos += 4;

    for sib in siblings_vec {
        for v in sib {
            if write_u32_le(out, write_pos, v).is_none() {
                return 0;
            }
            write_pos += 4;
        }
    }

    // Hashes list
    for h in hashes_vec {
        for v in h {
            if write_u32_le(out, write_pos, v).is_none() {
                return 0;
            }
            write_pos += 4;
        }
    }

    if write_pos != total_size {
        return 0;
    }

    total_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_sign_verify_ssz() {
        // Generate key pair
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let activation_epoch = 0;
        let num_active_epochs = 10;
        
        let (pk, sk) = <HashSigScheme as SignatureScheme>::key_gen(&mut rng, activation_epoch, num_active_epochs);
        
        // Sign a message at epoch 1
        let message: [u8; 32] = [
            0x96, 0xfd, 0x6f, 0x2c, 0x91, 0x00, 0x83, 0x2c,
            0xdd, 0xdd, 0x6e, 0x06, 0xce, 0x9c, 0x7d, 0x62,
            0x91, 0x52, 0x71, 0x6a, 0xaa, 0x98, 0x21, 0xa4,
            0xfb, 0x97, 0x26, 0xdb, 0x01, 0xfe, 0xe3, 0xf2,
        ];
        let epoch: u32 = 1;
        
        let signature = <HashSigScheme as SignatureScheme>::sign(&sk, epoch, &message).expect("signing failed");
        
        // Verify the signature directly
        let is_valid = <HashSigScheme as SignatureScheme>::verify(&pk, epoch, &message, &signature);
        assert!(is_valid, "Direct verification failed");
        
        // Serialize to SSZ
        let pk_ssz = pk.as_ssz_bytes();
        let sig_ssz = signature.as_ssz_bytes();
        
        println!("pubkey SSZ length: {}", pk_ssz.len());
        println!("signature SSZ length: {}", sig_ssz.len());
        println!("signature SSZ first 36 bytes: {:02x?}", &sig_ssz[..36.min(sig_ssz.len())]);
        
        // Deserialize from SSZ
        let pk2 = HashSigPublicKey::from_ssz_bytes(&pk_ssz).expect("pubkey SSZ decode failed");
        let sig2 = HashSigSignature::from_ssz_bytes(&sig_ssz).expect("signature SSZ decode failed");
        
        // Verify with deserialized values
        let is_valid2 = <HashSigScheme as SignatureScheme>::verify(&pk2, epoch, &message, &sig2);
        assert!(is_valid2, "SSZ round-trip verification failed");
        
        println!("Round-trip test passed!");
    }
    
    #[test]
    fn test_verify_fixture_signature() {
        // This is the exact fixture data from test_proposer_signature
        // pubkey from fixture (52 bytes) - validator index 1
        let pubkey_bytes: [u8; 52] = [
            0x8c, 0x73, 0xc3, 0x73, 0xd9, 0x84, 0x68, 0x2c,
            0x35, 0x91, 0x91, 0x47, 0x80, 0x6c, 0x6d, 0x39,
            0x19, 0x42, 0x03, 0x6c, 0x2b, 0xd8, 0xf3, 0x59,
            0xe6, 0x81, 0x53, 0x0e, 0x44, 0x44, 0x3c, 0x15,
            0xfb, 0x9a, 0x15, 0x71, 0xfe, 0x4e, 0x95, 0x7a,
            0xab, 0xc2, 0x0f, 0x5f, 0xbc, 0x67, 0xb8, 0x6c,
            0x8a, 0x16, 0xa2, 0x09,
        ];
        
        // message hash (32 bytes) - computed from AttestationData
        let message: [u8; 32] = [
            0x96, 0xfd, 0x6f, 0x2c, 0x91, 0x00, 0x83, 0x2c,
            0xdd, 0xdd, 0x6e, 0x06, 0xce, 0x9c, 0x7d, 0x62,
            0x91, 0x52, 0x71, 0x6a, 0xaa, 0x98, 0x21, 0xa4,
            0xfb, 0x97, 0x26, 0xdb, 0x01, 0xfe, 0xe3, 0xf2,
        ];
        
        let epoch: u32 = 1;
        
        // Full signature SSZ bytes (3112 bytes) from Python
        let sig_ssz_hex = "24000000455d822a9938490a99373d435411556609dc7e4ebf86874bb500153d2804000004000000f7af5070abf022606aff6543ccb88f5b77a47a49203a2d5dbc04751b8088ef3110fe3d55c9b4b0348f20cf1dfb340176964cf23d9665305a5c5f2901803e5444dfe96a196246435baec3f546cb020151da0f9456df86a769f14df97a472b7d482a58086c28c5f24cc93a0b20834f78369e8d873b9239303009021b600ada8f4a6a1de3770f87b4089b217913929d963f7104a65e25cdda68f71677146c3a9f30f770804691f03e5155a00976ce09f228b3613d13f5bec86d4a07c51b0e22c778d071f029095778649ef4532d21fbc90358eb8375c7ba3234b8ed3f0addea5c21e17b390c4dc53b55c21fbc0e57f782243870d3683fbc357c5e4c695042826336210543687f7d5f35c586cc2afd8cca6e5fda3a073ebfac61f618de229ba2e9531c4ac73e8326815d6fab2e03b6ab9b199d5830052b00376771e0e2061fc35045d7f65d2317649117041a381fa6f75b0703e5c07388f74272a436e5190178f46d87185965fcf5f81902d3a90d355dbb535acb7877b2d3dd7dd48fd70dd6c58c51bbb5142e141aef69d2f9860635802a301c2aba382e3d635e3cad98361a436a727e31495c7e085e77e9fb4f3ef84efc0d083b3c4fd34af713e31dc909c4e1de3806fd1b5525de652832ff0379206a6333228e7573ba7f3d47d976ab5d1608b436260c0106c4531b123c1f592b00a34c0e2770ee3e55ef4a0f49745a2d4859b5688dda4d6883e6f024b3ebdf26a0345a515264e13be56a33356d00366052ba8507036a6b406f3682099436f749a24471646f4800021aa7644891c4bd34d5ff6f01df651a6f718a4317ff237d434e49e46c3c6a4c662fc3280e90b999170c0c5d7d5117eb49c9db8b14873df7516d5d0d1a1e81d32ca49fec4f3d02031a77fc621c5ea7537647eb3537a4396b6ce1d44c6ca841a612a93ce05e2bb000793431634460cef8314942940fe830cf4b84ca6e5e2abc210a30b10d42ec3f717daa25651ae5fb7f19b969245c8165a73a58d5800971be1b267dc036236fe2e811c2338e1100ec217e77bf36428392086a4fb3ab2ed0a918616ddcb1377b247f5b46f9cf442ac0a233700b9544149e2c0c6016a96487872049c04580561505ef3110023f2cb6cc90423ee59e22f241c158a69d8c7c32fee33d5615293992d32015aeadd4053eecfb2d1e27104a4583361dff7f7d338528ba6366215e510113913463bde83bfae70e505cb1416375aacb49b04b5c109404f45b65794a294874962518f71407aca3f118fcd7d171f0b49f0e63c55c10efdc713a7eed664fa54d7a6ca8015f4dd77b027d2e9d5c0f4573d24be8dc5f06787e5119e9ac014ab91b3200d923d47175c50e6fd9564f38ea33264dc1126e0c674b065824c6b0630158ae0fcdb772272958e43fc57a037a3abc1c2812e3820b70dd870c8786137c37965e060541e64bba13ce34ebc9071ff7360e23f9388d5b462c4c51972c0102a74e071125e1e46a3da3a552b1f79d2f8586b565a4aa162b9ae13d3dcacb981d278da8485f2a78292f6fee030d5262184260613f5e6c56601949ad4fe14f62377b82e80294f64b1f1f84961ecfc55f6a69cf943049fd5f31bccc2b34701482230511ba09fbd7380b4bac8a37df76170df000075fac9a586822768e11eb88eb3294eff850de72db6bcf605f6dc4c03e52cadc6479d5484727e430770a613c856a4873d866037bf444d2b73626ea3bcb49eafb5954dd1acc2e79a92c505a70cb37529dbc4ba8966d4269718a45d223021aee0b6e2346f51371b64cef342eaf24167ba1e90e25ad3c750a7b2663905a275cb1a9923e2a817d1ebc81760570739775773b4e2d31fb94042839475da2eee07992ffe03e38e0ec3a4b1077543ce70f0519efb306f62997753840035fc9c832715029157ec430e70a311af1092777fa228e87b85458c87d043cb22161a1b05257dfc9f178a2a8826d582a2f5e35ddfd124adff24df025612a685cd4305dedc50bc4a2e54483170f3159ccf128abb485442e9ff84b145a3e0fd683a27859152352b966d82ffaf3df7991ebb124916c26677e6a6112aaa141151a971e47aff3545ee8cd984954ba2507ceda772464bf12722396bc207ca82a2499468252b1e65e4bd2f2ba787b2ac1579f022b12ee6f9c612e378611bf688f3197c5eb67b045e923facf60463d124943329eba045107a931caf77b6dfad2966526bfc317f4edbb3163beed337c89477ca6230e79d858150df505a9468439df5ac29512005e12c94017816c768a8f57181cc5d72be17a9171d818f27c16acc734a5465845639ba6236d1c8e041e9cef56c220fd72d358867be26ef05fb11d866bcba0b26852cc7d5c3f8952136da1ab79d9706465a921036bf0303126ce8f364baabdf8340c25d55937fa980af44d586631c7871e37a7a307f0feee69c4ce77241089dc127b883b694aab6c60723a3f5ec346463c6eb4e5506d062c4fbba8810854bd380ae6b27f71d131bc66c198383f99fc834ddb79f15f0c71bd463b325c02f913e74f72acf25db6df63510b416776ee55f217dd5544632a758c3c2c0a946936efdf6d1478391d25072425da54d341101a0a30ed21893571252f5c3b7af659261d7a3a5afe7b0842f8a45496d81449901f9065cca99e00a1c33c26342a423814e68306d14ba87b827aea602fc18a0dcb25c90e94293e62c0653825ec9c336180575064725fd92c47f28655b7d41e106cd04b432fe3f57de4c66c28a261c06a2966a9214b2b186328bad843bce57a21ff3c0408e895e912f654743a666f7e346365b6499c38037438524138f54e6c12dad7b631fee08d2298656575ed77727460a56010ffc98977117b355216a0e164ca433b43a615ab21f0f2350ad3630f27ae2b6f1893b9684174e7715f2b71534951f3f1029025116c4f981f692dcaae5dda712637cb5dc805f3623a190aa97f68e3c29609e47009072816bc35fca50878aea84434e4b71a4ba7067a34ad637c1806be197af81f973e73d0a21891d0f057df69ee5372b8984578a8f902554530505b8ee4238f355d18dbb5f32ddfa55c6d6abc6a7d810fa267d4f7953313c4424bfa59bb248a7bdc593edbb63f31e8725128e48c71846cd8326ef48b4d986eb12156236412d0e612063bec1b112680b7592e43670e3c052623cf2f390baa322f7938419b498d035941e5af38751ced916cbf35ca31f4f6e76b05f45b2b8d3f865ba5655715a132303571e93d08cb40e954cf01a46aef20870f16bb6c48ff995f3b33e982712faa34695d515b3a250f580f8699bd7bb61add70fb010f4d2c14101648914d3d1b92b250890bb6202c66b64de4d29c6486c5b85e6d2d470dd0a22252197a2442e9b8ea4abe07411010c59e76407d3c217053fa3a3b473b7df06bc47663d7093e9417057e77bdda1d33b1504aac12f2705f608e4862323b12dfb9012d2928a11a80061639fae63c4b39674078cfc58d48ec365979675935303f62b3210582de04314a0b3514f6370cc941cf4b29d4d63a924900382a222758dbaa561c1eb2ba555ba1951a51be49346588d212741c0d5b35ffa615384bf822cbe4496eb5bede106aeb3f5f4448eb4bacb9ff23974705339fdc0725f24d865b3209130d6cd7d43223b7a5483c8e154033bad826a102af29187d3754cae56859777570576e281c5a8cfe7d35c9d1c96f6882243cc6eeb05251b81b22a0e95e60e3e64e3acf1b0b1c24501d2f378d533196bb5320a47c4c61aefa156d8f41422edf9add7953e03b1b88ca67109b66a06c7abbd00a931635674c3a9c6063a68a4f9f670569268061686cad8c1da5c3531a3f43524007fa45149ef61a6adcf932280df4fe44676bb33dd51a882b5e582b0f1f83b45eca9530715efe080c2d872b52ca02b257b8ff02547b7e05433266205408d2131d6963054482c0be3533c8b46829cfe03a29e3f2211da6871de53ef407e17ce42366a1d8247327b9227c2f8c398c9c3c4acefdcd414045043fb8816d38bf1ac050152eca666bef806e896f77410b1d972668bdc05a0eb53f61541cc74b1494fb62bf5ee301800a8560d62b6b28c369714180c8e9178544b3674e2a0471ca77b33f7c2b2722a41d57558c7fd7193ef1fa21ee650606d348ed0e035a8059cb906276bea4db7c97cc8b17879831620935c7527df8137da314c72109da24600c91fb2b5aa721409db66c244c269b3a65a40910fb441b553a43ca4ab4e63b3ffb05402ec974a463779b63425a3f996f04b9526e6987223cfcd2422d9d62b13cc571c5131906503db5a4d9314a1b6f60a0ee741b62f9e50d5e45df695b8080618824100e";
        
        let sig_bytes = hex::decode(sig_ssz_hex).expect("Invalid hex");
        assert_eq!(sig_bytes.len(), 3112, "Signature length mismatch");
        
        // Decode pubkey
        let pk = HashSigPublicKey::from_ssz_bytes(&pubkey_bytes).expect("Pubkey decode failed");
        println!("Pubkey decoded successfully");
        
        // Decode signature
        let sig = HashSigSignature::from_ssz_bytes(&sig_bytes).expect("Signature decode failed");
        println!("Signature decoded successfully");
        
        // Verify SSZ roundtrip
        let pk_rt = pk.as_ssz_bytes();
        let sig_rt = sig.as_ssz_bytes();
        assert_eq!(&pubkey_bytes[..], &pk_rt[..], "Pubkey SSZ roundtrip mismatch");
        assert_eq!(&sig_bytes[..], &sig_rt[..], "Signature SSZ roundtrip mismatch");
        println!("SSZ roundtrips OK");
        
        // Verify
        let is_valid = <HashSigScheme as SignatureScheme>::verify(&pk, epoch, &message, &sig);
        println!("Verification result: {}", is_valid);
        
        // This is the key test - should pass if everything is correct
        assert!(is_valid, "Signature verification failed!");
    }
    
    #[test]
    fn test_poseidon2_consistency() {
        // Test that our Poseidon2 output matches Python's output
        // Using test vectors from leanSpec tests/lean_spec/subspecs/poseidon2/test_permutation.py
        use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
        use p3_symmetric::Permutation;
        use p3_field::{PrimeCharacteristicRing, PrimeField32};
        
        let perm = default_koalabear_poseidon2_16();
        
        // Input from leanSpec test_permutation.py INPUT_16:
        let input_vals: [u32; 16] = [
            894848333, 1437655012, 1200606629, 1690012884,
            71131202, 1749206695, 1717947831, 120589055,
            19776022, 42382981, 1831865506, 724844064,
            171220207, 1299207443, 227047920, 1783754913,
        ];
        
        let mut state: [KoalaBear; 16] = core::array::from_fn(|i| KoalaBear::from_u64(input_vals[i] as u64));
        
        println!("Input: {:?}", state.map(|x| x.as_canonical_u32()));
        
        perm.permute_mut(&mut state);
        
        let output: Vec<u32> = state.iter().map(|x| x.as_canonical_u32()).collect();
        println!("Output: {:?}", output);
        
        // Expected from leanSpec test_permutation.py EXPECTED_16:
        let expected: [u32; 16] = [
            1934285469, 604889435, 133449501, 1026180808,
            1830659359, 176667110, 1391183747, 351743874,
            1238264085, 1292768839, 2023573270, 1201586780,
            1360691759, 1230682461, 748270449, 651545025,
        ];
        
        for (i, (got, exp)) in output.iter().zip(expected.iter()).enumerate() {
            if got != exp {
                println!("Mismatch at index {}: got {}, expected {}", i, got, exp);
            }
        }
        
        assert_eq!(output.as_slice(), &expected[..], "Poseidon2 output mismatch with leanSpec vectors!");
        println!("Poseidon2 consistency test passed!");
    }
}
