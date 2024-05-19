
use aes_gcm::AeadCore;
use cas_lib::sponges::{ascon_aead::AsconAead, cas_ascon_aead::CASAsconAead};
use napi_derive::napi;

#[napi]
pub fn ascon128_key_generate() -> Vec<u8> {
    return <AsconAead as CASAsconAead>::generate_key();
}

#[test]
fn test_ascon128_key_generate() {
    let key = ascon128_key_generate();
    assert_eq!(key.len(), 16);
}

#[napi]
pub fn ascon128_nonce_generate() -> Vec<u8> {
    return <AsconAead as CASAsconAead>::generate_nonce();
}

#[test]
pub fn test_ascon128_nonce_generate() {
    let nonce = ascon128_nonce_generate();
    assert_eq!(nonce.len(), 16);
}

#[napi]
pub fn ascon128_encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    return <AsconAead as CASAsconAead>::encrypt(key, nonce, plaintext);
}

#[test]
pub fn test_ascon128_encrypt() {
    let key = <AsconAead as CASAsconAead>::generate_key();
    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let plaintext = b"Hello, World!".to_vec();
    let ciphertext = ascon128_encrypt(key.clone(), nonce.clone(), plaintext.clone());
    assert_ne!(ciphertext, plaintext);
}

#[napi]
pub fn ascon128_decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    return <AsconAead as CASAsconAead>::decrypt(key, nonce, ciphertext);
}

#[test]
pub fn test_ascon128_decrypt() {
    let key = <AsconAead as CASAsconAead>::generate_key();
    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let plaintext = b"Hello, World!".to_vec();
    let ciphertext = ascon128_encrypt(key.clone(), nonce.clone(), plaintext.clone());
    let decrypted = ascon128_decrypt(key.clone(), nonce.clone(), ciphertext.clone());
    assert_eq!(decrypted, plaintext);
}