use leansig::{signature::SignatureScheme, MESSAGE_LENGTH};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

const PROD_SIGNATURE_SSZ_LEN: usize = 3112;
const TEST_SIGNATURE_SSZ_LEN: usize = 424;

#[repr(u8)]
enum HashSigSchemeId {
    Test = 0,
    Prod = 1,
}

/// Production instantiation (LeanSpec `prod`).
pub type HashSigSchemeProd =
    leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

/// Test instantiation matching LeanSpec `LEAN_ENV=test` constants.
///
/// LeanSpec test config:
/// - MESSAGE_LENGTH=32
/// - LOG_LIFETIME=8
/// - DIMENSION=4
/// - BASE=4
/// - FINAL_LAYER=6
/// - TARGET_SUM=6
/// - PARAMETER_LEN=5
/// - TWEAK_LEN_FE=2
/// - MSG_LEN_FE=9
/// - RAND_LEN_FE=7
/// - HASH_LEN_FE=8
/// - CAPACITY=9
/// - POS_OUTPUT_LEN_PER_INV_FE=15
/// - POS_INVOCATIONS=1
pub type HashSigSchemeTest = leansig::signature::generalized_xmss::GeneralizedXMSSSignatureScheme<
    leansig::symmetric::prf::shake_to_field::ShakePRFtoF<8, 7>,
    leansig::inc_encoding::target_sum::TargetSumEncoding<
        leansig::symmetric::message_hash::top_level_poseidon::TopLevelPoseidonMessageHash<
            15,
            1,
            15,
            4,
            4,
            6,
            2,
            9,
            5,
            7,
        >,
        6,
    >,
    leansig::symmetric::tweak_hash::poseidon::PoseidonTweakHash<5, 8, 2, 9, 4>,
    8,
>;

pub type HashSigScheme = HashSigSchemeProd;

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
    scheme_id: u8,
) -> i32 {
    if pubkey_bytes.is_null() || message.is_null() || signature_bytes.is_null() {
        return -1;
    }

    unsafe {
        let expected_len = match scheme_id {
            x if x == HashSigSchemeId::Test as u8 => TEST_SIGNATURE_SSZ_LEN,
            x if x == HashSigSchemeId::Prod as u8 => PROD_SIGNATURE_SSZ_LEN,
            _ => return -1,
        };

        if signature_len != expected_len {
            return -1;
        }

        let pk_data = slice::from_raw_parts(pubkey_bytes, pubkey_len);
        let sig_data = slice::from_raw_parts(signature_bytes, signature_len);
        let msg_data = slice::from_raw_parts(message, MESSAGE_LENGTH);

        let message_array: &[u8; MESSAGE_LENGTH] = match msg_data.try_into() {
            Ok(arr) => arr,
            Err(_) => return -1,
        };

        fn verify_with_scheme<S: SignatureScheme>(
            pk_data: &[u8],
            sig_data: &[u8],
            epoch: u32,
            message_array: &[u8; MESSAGE_LENGTH],
        ) -> Result<bool, ()> {
            let pk = S::PublicKey::from_ssz_bytes(pk_data).map_err(|_| ())?;
            let sig = S::Signature::from_ssz_bytes(sig_data).map_err(|_| ())?;
            Ok(S::verify(&pk, epoch, message_array, &sig))
        }

        let attempt: Result<bool, ()> = match scheme_id {
            x if x == HashSigSchemeId::Test as u8 => {
                verify_with_scheme::<HashSigSchemeTest>(pk_data, sig_data, epoch, message_array)
            }
            x if x == HashSigSchemeId::Prod as u8 => {
                verify_with_scheme::<HashSigSchemeProd>(pk_data, sig_data, epoch, message_array)
            }
            _ => return -1,
        };

        match attempt {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(()) => -1,
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
///
/// # Safety
/// - `signature_json_ptr` must be either null or point to `signature_json_len` readable bytes.
/// - `out_ptr` must be either null or point to `out_len` writable bytes.
/// - Both buffers must be valid for the duration of the call and must not overlap in a way that
///   violates Rust aliasing rules.
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

    let path_variable_size = siblings_vec.len().saturating_mul(sibling_size);
    let path_total_size = match path_fixed_part.checked_add(path_variable_size) {
        Some(v) => v,
        None => return 0,
    };

    let hashes_size = hashes_vec.len().saturating_mul(hash_size);

    let total_size = match sig_fixed_part
        .checked_add(path_total_size)
        .and_then(|v| v.checked_add(hashes_size))
    {
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
