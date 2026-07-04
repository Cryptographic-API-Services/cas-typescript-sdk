use cas_lib::symmetric::{cas_symmetric_encryption::Chacha20Poly1305Encryption, chacha20poly1305::CASChacha20Poly1305};
use napi_derive::napi;

#[napi]
pub fn chacha20_poly1305_key() -> Vec<u8> {
    return <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_key();
}

#[napi]
pub fn chacha20_poly1305_nonce() -> Vec<u8> {
    return <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_nonce();
}

#[napi]
pub fn chacha20_poly1305_encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as Chacha20Poly1305Encryption>::encrypt_plaintext(key, nonce, plaintext))
}

#[napi]
pub fn chacha20_poly1305_decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as Chacha20Poly1305Encryption>::decrypt_ciphertext(key, nonce, ciphertext))
}

#[test]
fn chacha20_poly1305_encrypt_decrypt_test() {
    let key = chacha20_poly1305_key();
    let nonce = chacha20_poly1305_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = chacha20_poly1305_encrypt(key.clone(), nonce.clone(), plaintext.clone()).unwrap();
    let decrypted_plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext).unwrap();
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
fn chacha20_poly1305_decrypt_tampered_ciphertext_fails_test() {
    let key = chacha20_poly1305_key();
    let nonce = chacha20_poly1305_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let mut ciphertext = chacha20_poly1305_encrypt(key.clone(), nonce.clone(), plaintext).unwrap();
    ciphertext[0] ^= 0xff;
    assert!(chacha20_poly1305_decrypt(key, nonce, ciphertext).is_err());
}

#[test]
fn chacha20_poly1305_rejects_bad_key_and_nonce_lengths_test() {
    let key = chacha20_poly1305_key();
    let nonce = chacha20_poly1305_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    assert!(chacha20_poly1305_encrypt(vec![0u8; 16], nonce, plaintext.clone()).is_err());
    assert!(chacha20_poly1305_encrypt(key, vec![0u8; 8], plaintext).is_err());
}
