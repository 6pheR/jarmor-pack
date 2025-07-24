// Declare and expose crypto modules
pub mod aes256gcm;
pub mod aes128gcm;
pub mod xchacha20;
pub mod aescbc_hmac;
pub mod common;

use std::collections::HashMap;
use aes256gcm::encrypt_aes256gcm;
use aes128gcm::encrypt_aes128gcm;
use xchacha20::encrypt_xchacha20;
use aescbc_hmac::encrypt_aes_cbc_hmac;
use common::EncryptionAlgorithm;

/// Prints the list of available encryption algorithms
pub fn list_algorithms() {
    println!("Supported algorithms:");
    println!("- aes256gcm (default)");
    println!("- aes128gcm");
    println!("- xchacha20");
    println!("- aescbc_hmac");
}

/// Calls the encryption function based on selected algorithm
pub fn encrypt_file(
    input_path: &str,
    output_path: &str,
    key: &str,
    algo: &str,
) -> Result<(), String> {
    // Map algorithm names to enum variants
    let algorithms: HashMap<&str, EncryptionAlgorithm> = HashMap::from([
        ("aes256gcm", EncryptionAlgorithm::Aes256Gcm),
        ("aes128gcm", EncryptionAlgorithm::Aes128Gcm),
        ("xchacha20", EncryptionAlgorithm::XChaCha20),
        ("aescbc_hmac", EncryptionAlgorithm::AesCbcHmac),
    ]);

    // Lookup algorithm by lowercase name
    let algo_key = algo.to_lowercase();
    let algorithm = algorithms
        .get(algo_key.as_str())
        .ok_or_else(|| format!("Unsupported algorithm: {}", algo))?;

    // Run the selected encryption method
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => encrypt_aes256gcm(input_path, output_path, key),
        EncryptionAlgorithm::Aes128Gcm => encrypt_aes128gcm(input_path, output_path, key),
        EncryptionAlgorithm::XChaCha20 => encrypt_xchacha20(input_path, output_path, key),
        EncryptionAlgorithm::AesCbcHmac => encrypt_aes_cbc_hmac(input_path, output_path, key),
    }
}
