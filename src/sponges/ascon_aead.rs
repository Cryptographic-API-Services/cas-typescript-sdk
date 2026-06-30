
use cas_lib::sponges::{ascon_aead::AsconAead, cas_ascon_aead::CASAsconAead};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi]
pub fn ascon128_key_generate() -> Uint8Array {
    return <AsconAead as CASAsconAead>::generate_key().to_vec().into();
}

#[test]
fn test_ascon128_key_generate() {
    let key = ascon128_key_generate();
    assert_eq!(key.len(), 16);
}

#[napi]
pub fn ascon128_nonce_generate() -> Uint8Array {
    return <AsconAead as CASAsconAead>::generate_nonce().to_vec().into();
}

#[test]
pub fn test_ascon128_nonce_generate() {
    let nonce = ascon128_nonce_generate();
    assert_eq!(nonce.len(), 16);
}

#[napi]
pub fn ascon128_encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<AsconAead as CASAsconAead>::encrypt(key.to_vec(), nonce.to_vec(), plaintext.to_vec()))
        .map(Uint8Array::from)
}

#[test]
pub fn test_ascon128_encrypt() {
    let key = <AsconAead as CASAsconAead>::generate_key().to_vec();
    let nonce = <AsconAead as CASAsconAead>::generate_nonce().to_vec();
    let plaintext = b"Hello, World!".to_vec();
    let ciphertext = ascon128_encrypt(
        key.into(),
        nonce.into(),
        plaintext.clone().into(),
    ).unwrap();
    assert_ne!(ciphertext.to_vec(), plaintext);
}

#[napi]
pub fn ascon128_decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<AsconAead as CASAsconAead>::decrypt(key.to_vec(), nonce.to_vec(), ciphertext.to_vec()))
        .map(Uint8Array::from)
}

#[test]
pub fn test_ascon128_decrypt() {
    let key = <AsconAead as CASAsconAead>::generate_key().to_vec();
    let nonce = <AsconAead as CASAsconAead>::generate_nonce().to_vec();
    let plaintext = b"Hello, World!".to_vec();
    let ciphertext = ascon128_encrypt(
        key.clone().into(),
        nonce.clone().into(),
        plaintext.clone().into(),
    ).unwrap();
    let decrypted = ascon128_decrypt(
        key.into(),
        nonce.into(),
        ciphertext,
    ).unwrap();
    assert_eq!(decrypted.to_vec(), plaintext);
}
