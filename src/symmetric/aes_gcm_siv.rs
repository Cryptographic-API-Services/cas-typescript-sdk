use cas_lib::symmetric::{aes_gcm_siv::{CASAES128SIV, CASAES256SIV}, cas_symmetric_encryption::{CASAES128SIVAadEncryption, CASAES128SIVEncryption, CASAES256SIVAadEncryption, CASAES256SIVEncryption, CASAeadSeal}};
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
pub fn aes128_gcm_siv_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes128_gcm_siv_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes256_gcm_siv_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(aes_key, nonce, plaintext))
}

#[napi]
pub fn aes256_gcm_siv_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(aes_key, nonce, ciphertext))
}

#[napi]
pub fn aes128_gcm_siv_encrypt_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVAadEncryption>::encrypt_plaintext_with_aad(aes_key, nonce, plaintext, aad))
}

#[napi]
pub fn aes128_gcm_siv_decrypt_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVAadEncryption>::decrypt_ciphertext_with_aad(aes_key, nonce, ciphertext, aad))
}

#[napi]
pub fn aes256_gcm_siv_encrypt_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVAadEncryption>::encrypt_plaintext_with_aad(aes_key, nonce, plaintext, aad))
}

#[napi]
pub fn aes256_gcm_siv_decrypt_with_aad(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVAadEncryption>::decrypt_ciphertext_with_aad(aes_key, nonce, ciphertext, aad))
}

#[napi]
pub fn aes128_gcm_siv_seal(aes_key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAeadSeal>::seal(aes_key, plaintext, aad))
}

#[napi]
pub fn aes128_gcm_siv_open(aes_key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAeadSeal>::open(aes_key, sealed, aad))
}

#[napi]
pub fn aes256_gcm_siv_seal(aes_key: Vec<u8>, plaintext: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAeadSeal>::seal(aes_key, plaintext, aad))
}

#[napi]
pub fn aes256_gcm_siv_open(aes_key: Vec<u8>, sealed: Vec<u8>, aad: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAeadSeal>::open(aes_key, sealed, aad))
}

#[napi]
pub fn aes128_gcm_siv_key_from_x25519_shared_secret(shared_secret: Vec<u8>, public_key_a: Vec<u8>, public_key_b: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::key_from_x25519_shared_secret(shared_secret, public_key_a, public_key_b))
}

#[napi]
pub fn aes256_gcm_siv_key_from_x25519_shared_secret(shared_secret: Vec<u8>, public_key_a: Vec<u8>, public_key_b: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256SIV as CASAES256SIVEncryption>::key_from_x25519_shared_secret(shared_secret, public_key_a, public_key_b))
}

#[napi]
pub fn aes128_gcm_siv_key_from_vec(key_slice: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128SIV as CASAES128SIVEncryption>::key_from_vec(key_slice))
}

#[napi]
pub fn aes256_gcm_siv_key_from_vec(key_slice: Vec<u8>) -> crate::Result<Vec<u8>> {
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
fn aes_gcm_siv_aad_encrypt_decrypt_test() {
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"header".to_vec();
    let nonce = aes_gcm_siv_nonce();

    let key128 = aes128_gcm_siv_key();
    let ciphertext128 = aes128_gcm_siv_encrypt_with_aad(key128.clone(), nonce.clone(), plaintext.clone(), aad.clone()).unwrap();
    assert_eq!(aes128_gcm_siv_decrypt_with_aad(key128.clone(), nonce.clone(), ciphertext128.clone(), aad.clone()).unwrap(), plaintext);
    assert!(aes128_gcm_siv_decrypt_with_aad(key128.clone(), nonce.clone(), ciphertext128, b"other".to_vec()).is_err());
    assert_eq!(
        aes128_gcm_siv_encrypt_with_aad(key128.clone(), nonce.clone(), plaintext.clone(), vec![]).unwrap(),
        aes128_gcm_siv_encrypt(key128, nonce.clone(), plaintext.clone()).unwrap()
    );

    let key256 = aes256_gcm_siv_key();
    let ciphertext256 = aes256_gcm_siv_encrypt_with_aad(key256.clone(), nonce.clone(), plaintext.clone(), aad.clone()).unwrap();
    assert_eq!(aes256_gcm_siv_decrypt_with_aad(key256.clone(), nonce.clone(), ciphertext256.clone(), aad).unwrap(), plaintext);
    assert!(aes256_gcm_siv_decrypt_with_aad(key256.clone(), nonce.clone(), ciphertext256, vec![]).is_err());
    assert_eq!(
        aes256_gcm_siv_encrypt_with_aad(key256.clone(), nonce.clone(), plaintext.clone(), vec![]).unwrap(),
        aes256_gcm_siv_encrypt(key256, nonce, plaintext).unwrap()
    );
}

#[test]
fn aes_gcm_siv_seal_open_test() {
    let plaintext = b"WelcomeHome".to_vec();
    let aad = Some(b"header".to_vec());

    let key128 = aes128_gcm_siv_key();
    let sealed128 = aes128_gcm_siv_seal(key128.clone(), plaintext.clone(), aad.clone()).unwrap();
    assert_eq!(sealed128.len(), CASAES128SIV::NONCE_LEN + plaintext.len() + 16);
    assert_eq!(aes128_gcm_siv_open(key128.clone(), sealed128.clone(), aad.clone()).unwrap(), plaintext);
    assert!(aes128_gcm_siv_open(key128, sealed128, None).is_err());

    let key256 = aes256_gcm_siv_key();
    let sealed256 = aes256_gcm_siv_seal(key256.clone(), plaintext.clone(), None).unwrap();
    assert_eq!(aes256_gcm_siv_open(key256.clone(), sealed256.clone(), None).unwrap(), plaintext);
    let (nonce, ciphertext) = sealed256.split_at(CASAES256SIV::NONCE_LEN);
    assert_eq!(aes256_gcm_siv_decrypt(key256.clone(), nonce.to_vec(), ciphertext.to_vec()).unwrap(), plaintext);
    assert!(aes256_gcm_siv_open(key256, sealed256[..CASAES256SIV::NONCE_LEN + 15].to_vec(), None).is_err());
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
fn aes_gcm_siv_key_from_x25519_shared_secret_test() {
    use crate::key_exchange::x25519::{x25519_diffie_hellman, x25519_generate_secret_and_public_key};
    let alice = x25519_generate_secret_and_public_key();
    let bob = x25519_generate_secret_and_public_key();
    let alice_shared_secret = x25519_diffie_hellman(alice.secret_key, bob.public_key.clone()).unwrap();
    let bob_shared_secret = x25519_diffie_hellman(bob.secret_key, alice.public_key.clone()).unwrap();

    // Each side passes its own public key first; the order must not matter.
    let alice_key_128 = aes128_gcm_siv_key_from_x25519_shared_secret(alice_shared_secret.clone(), alice.public_key.clone(), bob.public_key.clone()).unwrap();
    let bob_key_128 = aes128_gcm_siv_key_from_x25519_shared_secret(bob_shared_secret.clone(), bob.public_key.clone(), alice.public_key.clone()).unwrap();
    assert_eq!(alice_key_128.len(), 16);
    assert_eq!(alice_key_128, bob_key_128);

    let alice_key_256 = aes256_gcm_siv_key_from_x25519_shared_secret(alice_shared_secret.clone(), alice.public_key.clone(), bob.public_key.clone()).unwrap();
    let bob_key_256 = aes256_gcm_siv_key_from_x25519_shared_secret(bob_shared_secret, bob.public_key.clone(), alice.public_key.clone()).unwrap();
    assert_eq!(alice_key_256.len(), 32);
    assert_eq!(alice_key_256, bob_key_256);
    assert_ne!(alice_key_256[..16], alice_key_128[..]);

    let gcm_key_256 = crate::symmetric::aes::aes_256_key_from_x25519_shared_secret(alice_shared_secret.clone(), alice.public_key.clone(), bob.public_key.clone()).unwrap();
    let gcm_key_128 = crate::symmetric::aes::aes_128_key_from_x25519_shared_secret(alice_shared_secret, alice.public_key, bob.public_key).unwrap();
    assert_ne!(gcm_key_256, alice_key_256);
    assert_ne!(gcm_key_128, alice_key_128);

    let nonce = aes_gcm_siv_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_gcm_siv_encrypt(alice_key_256, nonce.clone(), plaintext.clone()).unwrap();
    let decrypted = aes256_gcm_siv_decrypt(bob_key_256, nonce, ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes_gcm_siv_key_from_vec_rejects_bad_length_test() {
    assert!(aes128_gcm_siv_key_from_vec(vec![0u8; 15]).is_err());
    assert!(aes256_gcm_siv_key_from_vec(vec![0u8; 31]).is_err());
    assert!(aes128_gcm_siv_key_from_vec(vec![0u8; 16]).is_ok());
    assert!(aes256_gcm_siv_key_from_vec(vec![0u8; 32]).is_ok());
}
