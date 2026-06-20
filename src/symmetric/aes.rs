use cas_lib::symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption}};
use napi_derive::napi;

#[napi]
pub fn aes_nonce() -> Vec<u8> {
    return <CASAES256 as CASAES256Encryption>::generate_nonce().to_vec();
}

#[napi]
pub fn aes128_key() -> Vec<u8> {
    return <CASAES128 as CASAES128Encryption>::generate_key().to_vec();
}

#[napi]
pub fn aes256_key() -> Vec<u8> {
    return <CASAES256 as CASAES256Encryption>::generate_key().to_vec();
}

#[napi]
pub fn aes128_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes128_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes256_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes256_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes_256_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(shared_secret))
}

#[napi]
pub fn aes_128_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(shared_secret))
}

#[test]
fn aes128_encrypt_decrypt_test() {
    let aes_key = aes128_key();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes128_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone()).unwrap();
    let decrypted_plaintext = aes128_decrypt(aes_key, nonce, ciphertext).unwrap();
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
fn aes256_encrypt_decrypt_test() {
    let aes_key = aes256_key();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone()).unwrap();
    let decrypted_plaintext = aes256_decrypt(aes_key, nonce, ciphertext).unwrap();
    assert_eq!(decrypted_plaintext, plaintext)
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
    assert_eq!(alice_key, bob_key);
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
    assert_eq!(alice_key, bob_key);
}
