use cas_lib::symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption}};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi]
pub fn aes_nonce() -> Uint8Array {
    return <CASAES256 as CASAES256Encryption>::generate_nonce().to_vec().into();
}

#[napi]
pub fn aes128_key() -> Uint8Array {
    return <CASAES128 as CASAES128Encryption>::generate_key().to_vec().into();
}

#[napi]
pub fn aes256_key() -> Uint8Array {
    return <CASAES256 as CASAES256Encryption>::generate_key().to_vec().into();
}

#[napi]
pub fn aes128_encrypt(aes_key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::encrypt_plaintext(aes_key.to_vec(), nonce.to_vec(), plaintext.to_vec()))
        .map(Uint8Array::from)
}

#[napi]
pub fn aes128_decrypt(aes_key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::decrypt_ciphertext(aes_key.to_vec(), nonce.to_vec(), ciphertext.to_vec()))
        .map(Uint8Array::from)
}

#[napi]
pub fn aes256_encrypt(aes_key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::encrypt_plaintext(aes_key.to_vec(), nonce.to_vec(), plaintext.to_vec()))
        .map(Uint8Array::from)
}

#[napi]
pub fn aes256_decrypt(aes_key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key.to_vec(), nonce.to_vec(), ciphertext.to_vec()))
        .map(Uint8Array::from)
}

#[napi]
pub fn aes_256_key_from_x25519_shared_secret(
    shared_secret: Uint8Array,
) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(shared_secret.to_vec()))
        .map(Uint8Array::from)
}

#[napi]
pub fn aes_128_key_from_x25519_shared_secret(
    shared_secret: Uint8Array,
) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(shared_secret.to_vec()))
        .map(Uint8Array::from)
}

#[cfg(test)]
fn vec(bytes: Uint8Array) -> Vec<u8> {
    bytes.to_vec()
}

#[test]
fn aes128_encrypt_decrypt_test() {
    // Uint8Array isn't Clone, so hold key/nonce as Vec<u8> and build a fresh
    // Uint8Array view for each FFI call.
    let aes_key = aes128_key().to_vec();
    let nonce = aes_nonce().to_vec();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes128_encrypt(aes_key.clone().into(), nonce.clone().into(), plaintext.clone().into()).unwrap();
    let decrypted_plaintext = aes128_decrypt(aes_key.into(), nonce.into(), ciphertext).unwrap();
    assert_eq!(vec(decrypted_plaintext), plaintext)
}

#[test]
fn aes256_encrypt_decrypt_test() {
    let aes_key = aes256_key().to_vec();
    let nonce = aes_nonce().to_vec();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_encrypt(aes_key.clone().into(), nonce.clone().into(), plaintext.clone().into()).unwrap();
    let decrypted_plaintext = aes256_decrypt(aes_key.into(), nonce.into(), ciphertext).unwrap();
    assert_eq!(vec(decrypted_plaintext), plaintext)
}

#[test]
fn aes_256_key_from_x25519_shared_secret_test() {
    use crate::key_exchange::x25519::{x25519_diffie_hellman, x25519_generate_secret_and_public_key};
    let alice = x25519_generate_secret_and_public_key();
    let bob = x25519_generate_secret_and_public_key();
    let alice_shared_secret = x25519_diffie_hellman(alice.secret_key, bob.public_key).unwrap();
    let bob_shared_secret = x25519_diffie_hellman(bob.secret_key, alice.public_key).unwrap();

    let alice_key = aes_256_key_from_x25519_shared_secret(alice_shared_secret).unwrap();
    let bob_key = aes_256_key_from_x25519_shared_secret(bob_shared_secret).unwrap();
    // Both parties must derive the same 32-byte AES-256 key from their shared secret.
    assert_eq!(alice_key.len(), 32);
    assert_eq!(vec(alice_key), vec(bob_key));
}

#[test]
fn aes_128_key_from_x25519_shared_secret_test() {
    use crate::key_exchange::x25519::{x25519_diffie_hellman, x25519_generate_secret_and_public_key};
    let alice = x25519_generate_secret_and_public_key();
    let bob = x25519_generate_secret_and_public_key();
    let alice_shared_secret = x25519_diffie_hellman(alice.secret_key, bob.public_key).unwrap();
    let bob_shared_secret = x25519_diffie_hellman(bob.secret_key, alice.public_key).unwrap();

    let alice_key = aes_128_key_from_x25519_shared_secret(alice_shared_secret).unwrap();
    let bob_key = aes_128_key_from_x25519_shared_secret(bob_shared_secret).unwrap();
    // Both parties must derive the same 16-byte AES-128 key from their shared secret.
    assert_eq!(alice_key.len(), 16);
    assert_eq!(vec(alice_key), vec(bob_key));
}
