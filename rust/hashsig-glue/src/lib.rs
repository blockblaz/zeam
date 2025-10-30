use hashsig::{signature::SignatureScheme, MESSAGE_LENGTH};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W4;

pub type HashSigScheme = SIGWinternitzLifetime18W4;
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
    SigningFailed(hashsig::signature::SigningError),
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

    pub fn sign<R: Rng>(
        &self,
        rng: &mut R,
        message: &[u8; MESSAGE_LENGTH],
        epoch: u32,
    ) -> Result<Signature, SigningError> {
        Ok(Signature::new(
            <HashSigScheme as SignatureScheme>::sign(rng, &self.inner, epoch, message)
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

        let mut rng = rand::rng();
        let signature = match keypair_ref.private_key.sign(&mut rng, message_array, epoch) {
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
