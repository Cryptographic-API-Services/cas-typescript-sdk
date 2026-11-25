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
pub fn aes128_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes128_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes256_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes256_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes_256_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
    public_key_a: Vec<u8>,
    public_key_b: Vec<u8>,
) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(shared_secret, public_key_a, public_key_b))
}

#[napi]
pub fn aes_128_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
    public_key_a: Vec<u8>,
    public_key_b: Vec<u8>,
) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(shared_secret, public_key_a, public_key_b))
}

#[napi]
pub fn aes128_key_from_vec(key_slice: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128 as CASAES128Encryption>::key_from_vec(key_slice))
}

#[napi]
pub fn aes256_key_from_vec(key_slice: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256 as CASAES256Encryption>::key_from_vec(key_slice))
}

#[test]
fn aes_key_from_vec_rejects_bad_length_test() {
    assert!(aes128_key_from_vec(vec![0u8; 15]).is_err());
    assert!(aes256_key_from_vec(vec![0u8; 31]).is_err());
    assert!(aes128_key_from_vec(vec![0u8; 16]).is_ok());
    assert!(aes256_key_from_vec(vec![0u8; 32]).is_ok());
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
    let alice_shared_secret = x25519_diffie_hellman(alice.secret_key, bob.public_key.clone()).unwrap();
    let bob_shared_secret = x25519_diffie_hellman(bob.secret_key, alice.public_key.clone()).unwrap();

    let alice_key = aes_256_key_from_x25519_shared_secret(alice_shared_secret, alice.public_key.clone(), bob.public_key.clone()).unwrap();
    // Bob passes the public keys in the opposite order and must still derive the same key.
    let bob_key = aes_256_key_from_x25519_shared_secret(bob_shared_secret, bob.public_key, alice.public_key).unwrap();
    assert_eq!(alice_key.len(), 32);
    assert_eq!(alice_key, bob_key);
}

#[test]
fn aes_key_from_x25519_shared_secret_is_bound_to_cipher_and_public_keys_test() {
    use crate::key_exchange::x25519::{x25519_diffie_hellman, x25519_generate_secret_and_public_key};
    let alice = x25519_generate_secret_and_public_key();
    let bob = x25519_generate_secret_and_public_key();
    let mallory = x25519_generate_secret_and_public_key();
    let shared_secret = x25519_diffie_hellman(alice.secret_key, bob.public_key.clone()).unwrap();

    let key_256 = aes_256_key_from_x25519_shared_secret(shared_secret.clone(), alice.public_key.clone(), bob.public_key.clone()).unwrap();
    let key_128 = aes_128_key_from_x25519_shared_secret(shared_secret.clone(), alice.public_key.clone(), bob.public_key.clone()).unwrap();
    assert_ne!(key_256[..16], key_128[..]);

    let key_other_peer = aes_256_key_from_x25519_shared_secret(shared_secret.clone(), alice.public_key.clone(), mallory.public_key).unwrap();
    assert_ne!(key_256, key_other_peer);

    assert!(aes_256_key_from_x25519_shared_secret(vec![0u8; 32], alice.public_key.clone(), bob.public_key.clone()).is_err());
    assert!(aes_128_key_from_x25519_shared_secret(shared_secret, alice.public_key, vec![0u8; 31]).is_err());
}

#[test]
fn aes_128_key_from_x25519_shared_secret_test() {
    use crate::key_exchange::x25519::{x25519_diffie_hellman, x25519_generate_secret_and_public_key};
    let alice = x25519_generate_secret_and_public_key();
    let bob = x25519_generate_secret_and_public_key();
    let alice_shared_secret = x25519_diffie_hellman(alice.secret_key, bob.public_key.clone()).unwrap();
    let bob_shared_secret = x25519_diffie_hellman(bob.secret_key, alice.public_key.clone()).unwrap();

    let alice_key = aes_128_key_from_x25519_shared_secret(alice_shared_secret, alice.public_key.clone(), bob.public_key.clone()).unwrap();
    let bob_key = aes_128_key_from_x25519_shared_secret(bob_shared_secret, bob.public_key, alice.public_key).unwrap();
    assert_eq!(alice_key.len(), 16);
    assert_eq!(alice_key, bob_key);
}
