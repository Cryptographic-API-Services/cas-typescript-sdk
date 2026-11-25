use cas_lib::symmetric::{cas_symmetric_encryption::{CASAeadSeal, Chacha20Poly1305AadEncryption, Chacha20Poly1305Encryption}, chacha20poly1305::CASChacha20Poly1305};
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
pub fn chacha20_poly1305_encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as Chacha20Poly1305Encryption>::encrypt_plaintext(key, nonce, plaintext))
}

#[napi]
pub fn chacha20_poly1305_decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as Chacha20Poly1305Encryption>::decrypt_ciphertext(key, nonce, ciphertext))
}

#[napi]
pub fn chacha20_poly1305_encrypt_with_aad(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as Chacha20Poly1305AadEncryption>::encrypt_plaintext_with_aad(key, nonce, plaintext, aad))
}

#[napi]
pub fn chacha20_poly1305_decrypt_with_aad(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as Chacha20Poly1305AadEncryption>::decrypt_ciphertext_with_aad(key, nonce, ciphertext, aad))
}

#[napi]
pub fn chacha20_poly1305_seal(key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as CASAeadSeal>::seal(key, plaintext, aad))
}

#[napi]
pub fn chacha20_poly1305_open(key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASChacha20Poly1305 as CASAeadSeal>::open(key, sealed, aad))
}

#[test]
fn chacha20_poly1305_aad_encrypt_decrypt_test() {
    let key = chacha20_poly1305_key();
    let nonce = chacha20_poly1305_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"header".to_vec();
    let ciphertext = chacha20_poly1305_encrypt_with_aad(key.clone(), nonce.clone(), plaintext.clone(), aad.clone()).unwrap();
    assert_eq!(chacha20_poly1305_decrypt_with_aad(key.clone(), nonce.clone(), ciphertext.clone(), aad).unwrap(), plaintext);
    assert!(chacha20_poly1305_decrypt_with_aad(key.clone(), nonce.clone(), ciphertext, b"other".to_vec()).is_err());
    assert_eq!(
        chacha20_poly1305_encrypt_with_aad(key.clone(), nonce.clone(), plaintext.clone(), vec![]).unwrap(),
        chacha20_poly1305_encrypt(key, nonce, plaintext).unwrap()
    );
}

#[test]
fn chacha20_poly1305_seal_open_test() {
    let key = chacha20_poly1305_key();
    let plaintext = b"WelcomeHome".to_vec();
    let aad = Some(b"header".to_vec());
    let sealed = chacha20_poly1305_seal(key.clone(), plaintext.clone(), aad.clone()).unwrap();
    assert_eq!(sealed.len(), CASChacha20Poly1305::NONCE_LEN + plaintext.len() + 16);
    assert_eq!(chacha20_poly1305_open(key.clone(), sealed.clone(), aad).unwrap(), plaintext);
    assert!(chacha20_poly1305_open(key.clone(), sealed.clone(), None).is_err());

    let unbound = chacha20_poly1305_seal(key.clone(), plaintext.clone(), None).unwrap();
    let (nonce, ciphertext) = unbound.split_at(CASChacha20Poly1305::NONCE_LEN);
    assert_eq!(chacha20_poly1305_decrypt(key.clone(), nonce.to_vec(), ciphertext.to_vec()).unwrap(), plaintext);
    assert!(chacha20_poly1305_open(key, sealed[..CASChacha20Poly1305::NONCE_LEN + 15].to_vec(), None).is_err());
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
    // Truncate freshly generated values rather than hard-coding wrong-length ones.
    let short_key = key[..16].to_vec();
    let short_nonce = nonce[..8].to_vec();
    assert!(chacha20_poly1305_encrypt(short_key, nonce, plaintext.clone()).is_err());
    assert!(chacha20_poly1305_encrypt(key, short_nonce, plaintext).is_err());
}
