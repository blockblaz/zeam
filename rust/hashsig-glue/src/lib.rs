// Re-export types from ream-post-quantum-crypto
pub use ream_post_quantum_crypto::hashsig::{
    errors::SignatureError, private_key::PrivateKey, public_key::PublicKey, signature::Signature,
};

use bincode::config::{Fixint, LittleEndian, NoLimit};
use hashsig::{signature::SignatureScheme, MESSAGE_LENGTH};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

// Import the HashSigScheme type from ream for bincode functions
use ream_post_quantum_crypto::hashsig::HashSigScheme;

type HashSigPublicKey = <HashSigScheme as SignatureScheme>::PublicKey;
type HashSigSignature = <HashSigScheme as SignatureScheme>::Signature;

// Bincode configuration matching ream's implementation
const BINCODE_CONFIG: bincode::config::Configuration<LittleEndian, Fixint, NoLimit> =
    bincode::config::standard().with_fixed_int_encoding();

/// KeyPair structure for FFI - holds both public and private keys
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
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

    let (public_key, private_key) = PrivateKey::generate_key_pair(
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

/// Sign a message
/// Returns pointer to Signature on success, null on error
/// # Safety
/// This is meant to be called from zig, so it's safe as the pointer will always exist
#[no_mangle]
pub unsafe extern "C" fn hashsig_sign(
    keypair: *const KeyPair,
    message_ptr: *const u8,
    epoch: u32,
) -> *mut Signature {
    if keypair.is_null() || message_ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let keypair_ref = &*keypair;
        let message_slice = slice::from_raw_parts(message_ptr, MESSAGE_LENGTH);

        // Convert slice to array
        let message_array: &[u8; MESSAGE_LENGTH] = match message_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        let signature = match keypair_ref.private_key.sign(message_array, epoch) {
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

/// Verify a signature
/// Returns 1 if valid, 0 if invalid, -1 on error
/// # Safety
/// This is meant to be called from zig, so it's safe as the pointer will always exist
#[no_mangle]
pub unsafe extern "C" fn hashsig_verify(
    keypair: *const KeyPair,
    message_ptr: *const u8,
    epoch: u32,
    signature: *const Signature,
) -> i32 {
    if keypair.is_null() || message_ptr.is_null() || signature.is_null() {
        return -1;
    }

    unsafe {
        let keypair_ref = &*keypair;
        let signature_ref = &*signature;
        let message_slice = slice::from_raw_parts(message_ptr, MESSAGE_LENGTH);

        // Convert slice to array
        let message_array: &[u8; MESSAGE_LENGTH] = match message_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return -1;
            }
        };

        match signature_ref.verify(&keypair_ref.public_key, epoch, message_array) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
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

/// Serialize a signature to bytes
/// Returns number of bytes written, or 0 on error
/// # Safety
/// buffer must point to a valid buffer of sufficient size
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
        let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);

        // The signature.inner is already the serialized form (FixedBytes)
        // Just copy the bytes directly without additional bincode serialization
        let sig_bytes = sig_ref.inner.as_slice();
        let len = sig_bytes.len().min(buffer_len);
        output_slice[..len].copy_from_slice(&sig_bytes[..len]);
        len
    }
}

/// Serialize a public key to bytes using bincode
/// Returns number of bytes written, or 0 on error
/// # Safety
/// buffer must point to a valid buffer of sufficient size
#[no_mangle]
pub unsafe extern "C" fn hashsig_pubkey_to_bytes(
    keypair: *const KeyPair,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if keypair.is_null() || buffer.is_null() {
        return 0;
    }

    unsafe {
        let keypair_ref = &*keypair;
        let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);

        let bytes = keypair_ref.public_key.to_bytes();
        let len = bytes.len().min(buffer_len);
        output_slice[..len].copy_from_slice(&bytes[..len]);
        len
    }
}

/// Verify XMSS signature from bincode-serialized bytes
/// Returns 1 if valid, 0 if invalid, -1 on error
/// # Safety
/// All pointers must be valid and point to correctly sized data
#[no_mangle]
pub unsafe extern "C" fn hashsig_verify_bincode(
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

        let pk: HashSigPublicKey = match bincode::serde::decode_from_slice(pk_data, BINCODE_CONFIG)
        {
            Ok((pk, _)) => pk,
            Err(_) => return -1,
        };

        let sig: HashSigSignature =
            match bincode::serde::decode_from_slice(sig_data, BINCODE_CONFIG) {
                Ok((sig, _)) => sig,
                Err(_) => return -1,
            };

        let is_valid = <HashSigScheme as SignatureScheme>::verify(&pk, epoch, message_array, &sig);

        if is_valid {
            1
        } else {
            0
        }
    }
}
