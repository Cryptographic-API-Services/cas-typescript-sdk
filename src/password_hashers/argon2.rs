
use napi_derive::napi;
use cas_lib::password_hashers::argon2::CASArgon;

#[napi]
pub fn argon2_hash(password: String) -> napi::Result<String> {
    crate::map_cas_err(CASArgon::hash_password(password))
}

#[napi]
pub fn argon2_verify(hashed_password: String, password_to_verify: String) -> napi::Result<bool> {
    crate::map_cas_err(CASArgon::verify_password(hashed_password, password_to_verify))
}

#[napi]
pub fn argon2_hash_params(memory_cost: u32, iterations: u32, parallelism: u32, password: String, ) -> napi::Result<String> {
    crate::map_cas_err(CASArgon::hash_password_parameters(memory_cost, iterations, parallelism, password))
}

#[napi]
pub fn argon2_derive_aes_128_key(password: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(CASArgon::derive_aes_128_key(password))
}

#[napi]
pub fn argon2_derive_aes_256_key(password: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(CASArgon::derive_aes_256_key(password))
}

#[test]
pub fn argon2_hash_params_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash_params(1024, 2, 1, password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_hash_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_verify_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone()).unwrap();
    let verified = argon2_verify(hashed, password).unwrap();
    assert_eq!(true, verified);
}

#[test]
pub fn argon2_derive_aes_128_key_test() {
    let password = b"ThisIsNotMyPasswolrd".to_vec();
    let key = argon2_derive_aes_128_key(password.clone()).unwrap();
    assert_eq!(key.len(), 16);
    // A random salt is generated per call, so the same password must not repeat a key.
    let second_key = argon2_derive_aes_128_key(password).unwrap();
    assert_ne!(key, second_key);
}

#[test]
pub fn argon2_derive_aes_256_key_test() {
    let password = b"ThisIsNotMyPasswolrd".to_vec();
    let key = argon2_derive_aes_256_key(password.clone()).unwrap();
    assert_eq!(key.len(), 32);
    let second_key = argon2_derive_aes_256_key(password).unwrap();
    assert_ne!(key, second_key);
}

#[test]
pub fn argon2_derive_aes_256_key_encrypt_decrypt_test() {
    use crate::symmetric::aes::{aes256_decrypt, aes256_encrypt, aes_nonce};
    let key = argon2_derive_aes_256_key(b"ThisIsNotMyPasswolrd".to_vec()).unwrap();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_encrypt(key.clone(), nonce.clone(), plaintext.clone()).unwrap();
    let decrypted_plaintext = aes256_decrypt(key, nonce, ciphertext).unwrap();
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
pub fn argon2_verify_fail_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone()).unwrap();
    let verified = "Nope".to_string();
    let verified = argon2_verify(hashed, verified).unwrap();
    assert_eq!(false, verified);
}
