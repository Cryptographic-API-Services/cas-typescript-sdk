use cas_lib::symmetric::{aes_gcm_siv::{CASAES128SIV, CASAES256SIV}, cas_symmetric_encryption::{CASAES128SIVEncryption, CASAES256SIVEncryption}};
use napi_derive::napi;

#[napi]
pub fn aes128_gcm_siv_key() -> Vec<u8> {
    return <CASAES128SIV as CASAES128SIVEncryption>::generate_key();
}

#[napi]
pub fn aes256_gcm_siv_key() -> Vec<u8> {
    return <CASAES256SIV as CASAES256SIVEncryption>::generate_key();
}

#[napi]
pub fn aes_gcm_siv_nonce() -> Vec<u8> {
    return <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce();
}

#[napi]
pub fn aes128_gcm_siv_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes128_gcm_siv_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes256_gcm_siv_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes256_gcm_siv_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes128_gcm_siv_key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::key_from_x25519_shared_secret(shared_secret))
}

#[napi]
pub fn aes256_gcm_siv_key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVEncryption>::key_from_x25519_shared_secret(shared_secret))
}

#[napi]
pub fn aes128_gcm_siv_key_from_vec(key_slice: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::key_from_vec(key_slice))
}

#[napi]
pub fn aes256_gcm_siv_key_from_vec(key_slice: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVEncryption>::key_from_vec(key_slice))
}

#[test]
fn aes128_gcm_siv_encrypt_decrypt_test() {
    let aes_key = aes128_gcm_siv_key();
    let nonce = aes_gcm_siv_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes128_gcm_siv_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone()).unwrap();
    let decrypted_plaintext = aes128_gcm_siv_decrypt(aes_key, nonce, ciphertext).unwrap();
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
fn aes256_gcm_siv_encrypt_decrypt_test() {
    let aes_key = aes256_gcm_siv_key();
    let nonce = aes_gcm_siv_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_gcm_siv_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone()).unwrap();
    let decrypted_plaintext = aes256_gcm_siv_decrypt(aes_key, nonce, ciphertext).unwrap();
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
fn aes256_gcm_siv_decrypt_tampered_ciphertext_fails_test() {
    let aes_key = aes256_gcm_siv_key();
    let nonce = aes_gcm_siv_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let mut ciphertext = aes256_gcm_siv_encrypt(aes_key.clone(), nonce.clone(), plaintext).unwrap();
    ciphertext[0] ^= 0xff;
    assert!(aes256_gcm_siv_decrypt(aes_key, nonce, ciphertext).is_err());
}

#[test]
fn aes_gcm_siv_key_from_vec_rejects_bad_length_test() {
    assert!(aes128_gcm_siv_key_from_vec(vec![0u8; 15]).is_err());
    assert!(aes256_gcm_siv_key_from_vec(vec![0u8; 31]).is_err());
    assert!(aes128_gcm_siv_key_from_vec(vec![0u8; 16]).is_ok());
    assert!(aes256_gcm_siv_key_from_vec(vec![0u8; 32]).is_ok());
}
