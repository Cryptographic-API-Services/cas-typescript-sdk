use aes_gcm::Key;
use cas_lib::symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::CASAESEncryption};
use napi_derive::napi;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::types::CASAesKeyFromX25519SharedSecret;

#[napi]
pub fn aes_nonce() -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut random_bytes = Vec::with_capacity(12);
    random_bytes.resize(12, 0);
    rng.fill_bytes(&mut random_bytes);
    random_bytes
}

#[napi]
pub fn aes128_key() -> Vec<u8> {
    return <CASAES128 as CASAESEncryption>::generate_key();
}

#[napi]
pub fn aes256_key() -> Vec<u8> {
    return <CASAES256 as CASAESEncryption>::generate_key();
}

#[napi]
pub fn aes128_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    return <CASAES128 as CASAESEncryption>::encrypt_plaintext(aes_key, nonce, plaintext);
}

#[napi]
pub fn aes128_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    return <CASAES128 as CASAESEncryption>::decrypt_ciphertext(aes_key, nonce, ciphertext);
}

#[napi]
pub fn aes256_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    return <CASAES256 as CASAESEncryption>::encrypt_plaintext(aes_key, nonce, plaintext);
}

#[napi]
pub fn aes256_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    return <CASAES256 as CASAESEncryption>::decrypt_ciphertext(aes_key, nonce, ciphertext);
}

#[napi]
pub fn aes_256_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
) -> CASAesKeyFromX25519SharedSecret {
    return <CASAES256 as CASAESEncryption>::key_from_x25519_shared_secret(shared_secret).into();
}

#[napi]
pub fn aes_128_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
) -> CASAesKeyFromX25519SharedSecret {
    return <CASAES128 as CASAESEncryption>::key_from_x25519_shared_secret(shared_secret).into();
}

#[test]
fn aes128_encrypt_decrypt_test() {
    let aes_key = aes128_key();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes128_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone());
    let decrypted_plaintext = aes128_decrypt(aes_key, nonce, ciphertext);
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
fn aes256_encrypt_decrypt_test() {
    let aes_key = aes256_key();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone());
    let decrypted_plaintext = aes256_decrypt(aes_key, nonce, ciphertext);
    assert_eq!(decrypted_plaintext, plaintext)
}
