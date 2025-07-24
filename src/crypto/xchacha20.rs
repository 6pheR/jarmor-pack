use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    XChaCha20Poly1305, XNonce,
};
use std::fs::{self, File};
use std::io::Write;

use super::common::derive_key;

pub fn encrypt_xchacha20(input_path: &str, output_path: &str, key_str: &str) -> Result<(), String> {
    // Derive a 256-bit key
    let key_bytes = derive_key(key_str, 32);
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // Generate a 192-bit nonce (XNonce)
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Read the plaintext file
    let plaintext = fs::read(input_path).map_err(|e| e.to_string())?;

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Write nonce + ciphertext to output
    let mut file = File::create(output_path).map_err(|e| e.to_string())?;
    file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
    file.write_all(&ciphertext).map_err(|e| e.to_string())?;

    Ok(())
}
