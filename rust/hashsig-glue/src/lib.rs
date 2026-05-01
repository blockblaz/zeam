// Production config (default)
#[cfg(not(feature = "test-config"))]
mod config {
    pub use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::{
        PubKeyAbortingTargetSumLifetime32Dim46Base8 as XmssPublicKey,
        SchemeAbortingTargetSumLifetime32Dim46Base8 as XmssScheme,
        SecretKeyAbortingTargetSumLifetime32Dim46Base8 as XmssSecretKey,
        SigAbortingTargetSumLifetime32Dim46Base8 as XmssSignature,
    };
}

// Test config
#[cfg(feature = "test-config")]
mod config {
    pub use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_8::{
        PubKeyAbortingTargetSumLifetime8Dim46Base8 as XmssPublicKey,
        SchemeAbortingTargetSumLifetime8Dim46Base8 as XmssScheme,
        SecretKeyAbortingTargetSumLifetime8Dim46Base8 as XmssSecretKey,
        SigAbortingTargetSumLifetime8Dim46Base8 as XmssSignature,
    };
}

use config::*;

use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use leansig::MESSAGE_LENGTH;

use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

pub type HashSigPublicKey = XmssPublicKey;
pub type HashSigSignature = XmssSignature;
pub type HashSigPrivateKey = XmssSecretKey;

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
    #[error("Signing failed")]
    SigningFailed,
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

    pub fn generate<R: rand::CryptoRng>(
        rng: &mut R,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> (PublicKey, Self) {
        let (pk, sk) =
            XmssScheme::key_gen(rng, activation_epoch as usize, num_active_epochs as usize);

        (PublicKey::new(pk), Self::new(sk))
    }

    pub fn sign(
        &self,
        message: &[u8; MESSAGE_LENGTH],
        epoch: u32,
    ) -> Result<Signature, SigningError> {
        let sig = XmssScheme::sign(&self.inner, epoch, message)
            .map_err(|_| SigningError::SigningFailed)?;
        Ok(Signature::new(sig))
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
        XmssScheme::verify(&public_key.inner, epoch, message, &self.inner)
    }
}

// SSZ serialization helpers (using leansig's Serializable trait)

fn xmss_public_key_from_ssz(bytes: &[u8]) -> Result<HashSigPublicKey, ()> {
    HashSigPublicKey::from_bytes(bytes).map_err(|_| ())
}

fn xmss_public_key_to_ssz(pk: &HashSigPublicKey) -> Vec<u8> {
    pk.to_bytes()
}

fn xmss_signature_from_ssz(bytes: &[u8]) -> Result<HashSigSignature, ()> {
    HashSigSignature::from_bytes(bytes).map_err(|_| ())
}

fn xmss_signature_to_ssz(sig: &HashSigSignature) -> Vec<u8> {
    sig.to_bytes()
}

fn xmss_secret_key_from_ssz(bytes: &[u8]) -> Result<HashSigPrivateKey, ()> {
    HashSigPrivateKey::from_bytes(bytes).map_err(|_| ())
}

fn xmss_secret_key_to_ssz(sk: &HashSigPrivateKey) -> Vec<u8> {
    sk.to_bytes()
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
        &mut StdRng::from_seed(seed),
        activation_epoch as u32,
        num_active_epochs as u32,
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

        let private_key: HashSigPrivateKey = match xmss_secret_key_from_ssz(sk_slice) {
            Ok(key) => key,
            Err(_) => {
                return ptr::null_mut();
            }
        };

        let public_key: HashSigPublicKey = match xmss_public_key_from_ssz(pk_slice) {
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
        let public_key: HashSigPublicKey = match xmss_public_key_from_ssz(pk_slice) {
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
        let signature: HashSigSignature = match xmss_signature_from_ssz(sig_slice) {
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

        let ssz_bytes = xmss_signature_to_ssz(&sig_ref.inner);

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

        let ssz_bytes = xmss_public_key_to_ssz(&public_key_ref.inner);

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

        let sk_bytes = xmss_secret_key_to_ssz(&private_key_ref.inner);

        if sk_bytes.len() > buffer_len {
            return 0;
        }

        let output_slice = slice::from_raw_parts_mut(buffer, buffer_len);
        output_slice[..sk_bytes.len()].copy_from_slice(&sk_bytes);
        sk_bytes.len()
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

        let pk: HashSigPublicKey = match xmss_public_key_from_ssz(pk_data) {
            Ok(pk) => pk,
            Err(_) => return -1,
        };

        let sig: HashSigSignature = match xmss_signature_from_ssz(sig_data) {
            Ok(sig) => sig,
            Err(_) => return -1,
        };

        let is_valid = XmssScheme::verify(&pk, epoch, message_array, &sig);

        if is_valid {
            1
        } else {
            0
        }
    }
}

// Test-scheme verify path. Always compiled, regardless of the test-config
// feature flag. Used by zeam's spec-test runner against leanSpec fixtures
// generated with leanEnv=test (LOG_LIFETIME=8, DIMENSION=4, ~424-byte signatures).
mod test_scheme {
    use leansig::serialization::Serializable;
    use leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_8::{
        PubKeyAbortingTargetSumLifetime8Dim46Base8 as TestPublicKey,
        SchemeAbortingTargetSumLifetime8Dim46Base8 as TestScheme,
        SigAbortingTargetSumLifetime8Dim46Base8 as TestSignature,
    };
    use leansig::signature::SignatureScheme;
    use leansig::MESSAGE_LENGTH;
    use std::slice;

    /// Verify a leanSpec test-scheme XMSS signature.
    ///
    /// Returns 1 if valid, 0 if invalid, -1 on parse / pointer error.
    ///
    /// # Safety
    /// All pointers must be valid for the supplied lengths.
    #[no_mangle]
    pub unsafe extern "C" fn hashsig_test_verify_ssz(
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

            let pk: TestPublicKey = match TestPublicKey::from_bytes(pk_data) {
                Ok(pk) => pk,
                Err(_) => return -1,
            };
            let sig: TestSignature = match TestSignature::from_bytes(sig_data) {
                Ok(sig) => sig,
                Err(_) => return -1,
            };

            if TestScheme::verify(&pk, epoch, message_array, &sig) {
                1
            } else {
                0
            }
        }
    }
}
