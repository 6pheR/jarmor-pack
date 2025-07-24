use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Write};

use super::common::derive_key;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn encrypt_aes_cbc_hmac(input_path: &str, output_path: &str, key_str: &str) -> Result<(), String> {
    // Read input data
    let mut file = File::open(input_path).map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| e.to_string())?;

    // Derive 64 bytes: 32 for AES, 32 for HMAC
    let derived = derive_key(key_str, 64);
    let (enc_key, hmac_key) = derived.split_at(32);

    // Generate IV (AES-CBC requires 16 bytes)
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Encrypt with AES-CBC
    let cipher = Aes256Cbc::new_from_slices(enc_key, &iv).map_err(|e| e.to_string())?;
    let ciphertext = cipher.encrypt_vec(&data);

    // HMAC over IV + ciphertext
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).map_err(|e| e.to_string())?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes();

    // Write IV + ciphertext + HMAC
    let mut out = File::create(output_path).map_err(|e| e.to_string())?;
    out.write_all(&iv).map_err(|e| e.to_string())?;
    out.write_all(&ciphertext).map_err(|e| e.to_string())?;
    out.write_all(&tag).map_err(|e| e.to_string())?;

    Ok(())
}
