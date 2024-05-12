
use aes_gcm::AeadCore;
use ascon_aead::{aead::{generic_array::GenericArray, Aead, KeyInit, OsRng}, Ascon128};
use napi_derive::napi;

use super::cas_ascon_aead::{CASAsconAead};
pub struct AsconAead;

impl CASAsconAead for AsconAead {
    fn encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let ciphertext = cipher.encrypt(&nonce_generic_array, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key_generic_array = GenericArray::from_slice(&key);
        let nonce_generic_array = GenericArray::from_slice(&nonce);
        let cipher = Ascon128::new(key_generic_array);
        let plaintext = cipher.decrypt(&nonce_generic_array, ciphertext.as_ref()).unwrap();
        plaintext
    }
    
    fn generate_key() -> Vec<u8> {
        return Ascon128::generate_key(&mut OsRng).to_vec();
    }
    
    fn generate_nonce() -> Vec<u8> {
        return Ascon128::generate_nonce(&mut OsRng).to_vec();
    }
}

#[napi]
pub fn ascon128_key_generate() -> Vec<u8> {
    return AsconAead::generate_key();
}

#[test]
fn test_ascon128_key_generate() {
    let key = ascon128_key_generate();
    assert_eq!(key.len(), 16);
}

#[napi]
pub fn ascon128_nonce_generate() -> Vec<u8> {
    return AsconAead::generate_nonce();
}

#[test]
pub fn test_ascon128_nonce_generate() {
    let nonce = ascon128_nonce_generate();
    assert_eq!(nonce.len(), 16);
}

#[napi]
pub fn ascon128_encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    return AsconAead::encrypt(key, nonce, plaintext);
}

#[test]
pub fn test_ascon128_encrypt() {
    let key = AsconAead::generate_key();
    let nonce = AsconAead::generate_nonce();
    let plaintext = b"Hello, World!".to_vec();
    let ciphertext = ascon128_encrypt(key.clone(), nonce.clone(), plaintext.clone());
    assert_ne!(ciphertext, plaintext);
}

#[napi]
pub fn ascon128_decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    return AsconAead::decrypt(key, nonce, ciphertext);
}

#[test]
pub fn test_ascon128_decrypt() {
    let key = AsconAead::generate_key();
    let nonce = AsconAead::generate_nonce();
    let plaintext = b"Hello, World!".to_vec();
    let ciphertext = ascon128_encrypt(key.clone(), nonce.clone(), plaintext.clone());
    let decrypted = ascon128_decrypt(key.clone(), nonce.clone(), ciphertext.clone());
    assert_eq!(decrypted, plaintext);
}