use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use std::fs::{self, File};
use std::io::Write;

use super::common::derive_key;

pub fn encrypt_aes256gcm(input_path: &str, output_path: &str, key_str: &str) -> Result<(), String> {
    // Derive a 256-bit key from the string
    let key_bytes = derive_key(key_str, 32);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate nonce (96 bits)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Read file and encrypt
    let plaintext = fs::read(input_path).map_err(|e| e.to_string())?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Write nonce + ciphertext
    let mut file = File::create(output_path).map_err(|e| e.to_string())?;
    file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
    file.write_all(&ciphertext).map_err(|e| e.to_string())?;

    Ok(())
}
