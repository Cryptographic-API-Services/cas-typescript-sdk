
use cas_lib::sponges::{ascon_aead::AsconAead, cas_ascon_aead::CASAsconAead};
use cas_lib::symmetric::cas_symmetric_encryption::CASAeadSeal;
use napi_derive::napi;

#[napi]
pub fn ascon128_key_generate() -> Vec<u8> {
    return <AsconAead as CASAsconAead>::generate_key().to_vec();
}

#[test]
fn test_ascon128_key_generate() {
    let key = ascon128_key_generate();
    assert_eq!(key.len(), 16);
}

#[napi]
pub fn ascon128_nonce_generate() -> Vec<u8> {
    return <AsconAead as CASAsconAead>::generate_nonce().to_vec();
}

#[test]
pub fn test_ascon128_nonce_generate() {
    let nonce = ascon128_nonce_generate();
    assert_eq!(nonce.len(), 16);
}

#[napi]
pub fn ascon128_encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<AsconAead as CASAsconAead>::encrypt(key, nonce, plaintext))
}

#[test]
pub fn test_ascon128_encrypt() {
    let key = <AsconAead as CASAsconAead>::generate_key();
    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let plaintext = b"Hello, World!";
    let ciphertext = ascon128_encrypt(
        key.clone().to_vec(),
        nonce.clone().to_vec(),
        plaintext.to_vec(),
    ).unwrap();
    assert_ne!(ciphertext, plaintext.to_vec());
}

#[napi]
pub fn ascon128_decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<AsconAead as CASAsconAead>::decrypt(key, nonce, ciphertext))
}

#[test]
pub fn test_ascon128_decrypt() {
    let key = <AsconAead as CASAsconAead>::generate_key();
    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let plaintext = b"Hello, World!";
    let ciphertext = ascon128_encrypt(
        key.clone().to_vec(),
        nonce.clone().to_vec(),
        plaintext.to_vec(),
    ).unwrap();
    let decrypted = ascon128_decrypt(
        key.clone().to_vec(),
        nonce.clone().to_vec(),
        ciphertext.clone(),
    ).unwrap();
    assert_eq!(decrypted, plaintext.to_vec());
}

#[napi]
pub fn ascon128_seal(key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<AsconAead as CASAeadSeal>::seal(key, plaintext, aad))
}

#[napi]
pub fn ascon128_open(key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<AsconAead as CASAeadSeal>::open(key, sealed, aad))
}

#[test]
pub fn test_ascon128_seal_open() {
    let key = ascon128_key_generate();
    let plaintext = b"Hello, World!".to_vec();
    let aad = Some(b"header".to_vec());
    let sealed = ascon128_seal(key.clone(), plaintext.clone(), aad.clone()).unwrap();
    assert_eq!(sealed.len(), AsconAead::NONCE_LEN + plaintext.len() + 16);
    assert_eq!(ascon128_open(key.clone(), sealed.clone(), aad).unwrap(), plaintext);
    assert!(ascon128_open(key.clone(), sealed.clone(), None).is_err());

    let unbound = ascon128_seal(key.clone(), plaintext.clone(), None).unwrap();
    let (nonce, ciphertext) = unbound.split_at(AsconAead::NONCE_LEN);
    assert_eq!(ascon128_decrypt(key.clone(), nonce.to_vec(), ciphertext.to_vec()).unwrap(), plaintext);
    assert!(ascon128_open(key, sealed[..AsconAead::NONCE_LEN + 15].to_vec(), None).is_err());
}