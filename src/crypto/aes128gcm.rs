use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use std::fs::{self, File};
use std::io::Write;
use crate::crypto::common::derive_key;

pub fn encrypt_aes128gcm(input_path: &str, output_path: &str, key_str: &str) -> Result<(), String> {
    // Derive a 128-bit key from input string
    let derived_key = derive_key(key_str, 16); // AES-128 needs 16 bytes
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&derived_key);
    let cipher = Aes128Gcm::new(key);

    // Generate a 96-bit nonce (standard for AES-GCM)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Read the input file
    let plaintext = fs::read(input_path).map_err(|e| e.to_string())?;

    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Write nonce + ciphertext to output file
    let mut file = File::create(output_path).map_err(|e| e.to_string())?;
    file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
    file.write_all(&ciphertext).map_err(|e| e.to_string())?;

    Ok(())
}
