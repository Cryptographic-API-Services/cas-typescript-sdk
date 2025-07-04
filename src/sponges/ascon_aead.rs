
use cas_lib::sponges::{ascon_aead::AsconAead, cas_ascon_aead::CASAsconAead};
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
pub fn ascon128_encrypt(key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    let key_arr: [u8; 16] = key.try_into().expect("Key must be 16 bytes");
    let nonce_arr: [u8; 16] = nonce.try_into().expect("Nonce must be 16 bytes");
    return <AsconAead as CASAsconAead>::encrypt(key_arr, nonce_arr, plaintext);
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
    );
    assert_ne!(ciphertext, plaintext.to_vec());
}

#[napi]
pub fn ascon128_decrypt(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let key_arr: [u8; 16] = key.try_into().expect("Key must be 16 bytes");
    let nonce_arr: [u8; 16] = nonce.try_into().expect("Nonce must be 16 bytes");
    return <AsconAead as CASAsconAead>::decrypt(key_arr, nonce_arr, ciphertext);
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
    );
    let decrypted = ascon128_decrypt(
        key.clone().to_vec(),
        nonce.clone().to_vec(),
        ciphertext.clone(),
    );
    assert_eq!(decrypted, plaintext.to_vec());
}