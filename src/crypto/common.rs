use sha2::{Sha256, Digest};
use hkdf::Hkdf;

/// Derives a key of given length using HKDF-SHA256.
/// Uses a deterministic salt based on the password itself.
pub fn derive_key(password: &str, length: usize) -> Vec<u8> {
    // Deterministic salt: hash("salt:" + password)
    // Not random to ensure signature stays consistent
    let mut hasher = Sha256::new();
    hasher.update(b"salt:");
    hasher.update(password.as_bytes());
    let salt = hasher.finalize();

    // Perform HKDF with the salt and password
    let hk = Hkdf::<Sha256>::new(Some(&salt), password.as_bytes());
    let mut okm = vec![0u8; length];
    hk.expand(b"jarmor-pack-kdf", &mut okm).expect("HKDF expand failed");

    okm
}

/// Supported encryption algorithms
#[derive(Clone)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    Aes128Gcm,
    XChaCha20,
    AesCbcHmac,
}
