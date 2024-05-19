use aes_gcm::Key;
use napi_derive::napi;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};

use super::cas_symmetric_encryption::{AesKeyFromX25519SharedSecret, CASAESEncryption};
pub struct CASAES128;
pub struct CASAES256;

impl CASAESEncryption for CASAES256 {
    fn generate_key() -> Vec<u8> {
        return Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let mut cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let mut cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret);
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = AesKeyFromX25519SharedSecret {
            aes_key: aes_key.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }
}

impl CASAESEncryption for CASAES128 {
    fn generate_key() -> Vec<u8> {
        return Aes128Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let mut cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        ciphertext
    }

    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let key = GenericArray::from_slice(&aes_key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        plaintext
    }

    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret {
        let mut aes_key: [u8; 16] = Default::default();
        aes_key.copy_from_slice(&shared_secret[..16]);
        let aes_key_slice = Key::<Aes128Gcm>::from_slice(&aes_key);
        let mut aes_nonce: [u8; 12] = Default::default();
        aes_nonce.copy_from_slice(&shared_secret[..12]);
        let result = AesKeyFromX25519SharedSecret {
            aes_key: aes_key_slice.to_vec(),
            aes_nonce: aes_nonce.to_vec(),
        };
        result
    }
}

#[napi]
pub fn aes_nonce() -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut random_bytes = Vec::with_capacity(12);
    random_bytes.resize(12, 0);
    rng.fill_bytes(&mut random_bytes);
    random_bytes
}

#[napi]
pub fn aes128_key() -> Vec<u8> {
    return CASAES128::generate_key();
}

#[napi]
pub fn aes256_key() -> Vec<u8> {
    return CASAES256::generate_key();
}

#[napi]
pub fn aes128_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    return CASAES128::encrypt_plaintext(aes_key, nonce, plaintext);
}

#[napi]
pub fn aes128_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    return CASAES128::decrypt_ciphertext(aes_key, nonce, ciphertext);
}

#[napi]
pub fn aes256_encrypt(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    return CASAES256::encrypt_plaintext(aes_key, nonce, plaintext);
}

#[napi]
pub fn aes256_decrypt(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    return CASAES256::decrypt_ciphertext(aes_key, nonce, ciphertext);
}

#[napi]
pub fn aes_256_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
) -> AesKeyFromX25519SharedSecret {
    return CASAES256::key_from_x25519_shared_secret(shared_secret);
}

#[napi]
pub fn aes_128_key_from_x25519_shared_secret(
    shared_secret: Vec<u8>,
) -> AesKeyFromX25519SharedSecret {
    return CASAES128::key_from_x25519_shared_secret(shared_secret);
}

#[test]
fn aes128_encrypt_decrypt_test() {
    let aes_key = aes128_key();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes128_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone());
    let decrypted_plaintext = aes128_decrypt(aes_key, nonce, ciphertext);
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
fn aes256_encrypt_decrypt_test() {
    let aes_key = aes256_key();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_encrypt(aes_key.clone(), nonce.clone(), plaintext.clone());
    let decrypted_plaintext = aes256_decrypt(aes_key, nonce, ciphertext);
    assert_eq!(decrypted_plaintext, plaintext)
}
