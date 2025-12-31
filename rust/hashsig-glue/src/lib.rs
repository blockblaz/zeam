use leansig::{signature::SignatureScheme, MESSAGE_LENGTH};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

pub type HashSigScheme =
    leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type HashSigPrivateKey = <HashSigScheme as SignatureScheme>::SecretKey;
pub type HashSigPublicKey = <HashSigScheme as SignatureScheme>::PublicKey;
pub type HashSigSignature = <HashSigScheme as SignatureScheme>::Signature;

pub struct PrivateKey {
    inner: HashSigPrivateKey,
}

pub struct PublicKey {
    pub inner: HashSigPublicKey,
}

pub struct Signature {
    pub inner: HashSigSignature,
}

/// KeyPair structure for FFI - holds both public and private keys
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
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    public_key_ptr: *const u8,
    public_key_len: usize,
) -> *mut KeyPair {
    if secret_key_ptr.is_null() || public_key_ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let sk_slice = slice::from_raw_parts(secret_key_ptr, secret_key_len);
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

        match signature_ref.verify(message_array, &keypair_ref.public_key, epoch) {
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

/// Serialize a public key to bytes using SSZ encoding
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

        // Directly SSZ encode the public key (leansig has SSZ support built-in)
        let ssz_bytes = keypair_ref.public_key.inner.as_ssz_bytes();

        if ssz_bytes.len() > buffer_len {
            return 0;
        }

        let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);
        output_slice[..ssz_bytes.len()].copy_from_slice(&ssz_bytes);
        ssz_bytes.len()
    }
}

/// Serialize a private key to bytes using SSZ encoding
/// Returns number of bytes written, or 0 on error
/// # Safety
/// buffer must point to a valid buffer of sufficient size
#[no_mangle]
pub unsafe extern "C" fn hashsig_privkey_to_bytes(
    keypair: *const KeyPair,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if keypair.is_null() || buffer.is_null() {
        return 0;
    }

    unsafe {
        let keypair_ref = &*keypair;

        // Directly SSZ encode the private key (leansig has SSZ support built-in)
        let ssz_bytes = keypair_ref.private_key.inner.as_ssz_bytes();

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

        // Directly SSZ decode (leansig has SSZ support built-in)
        let pk: HashSigPublicKey = match HashSigPublicKey::from_ssz_bytes(pk_data) {
            Ok(pk) => pk,
            Err(_) => return -1,
        };

        let sig: HashSigSignature = match HashSigSignature::from_ssz_bytes(sig_data) {
            Ok(sig) => sig,
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
