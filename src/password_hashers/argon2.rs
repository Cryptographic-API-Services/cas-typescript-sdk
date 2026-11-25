
use napi_derive::napi;
use cas_lib::password_hashers::argon2::CASArgon;

#[napi]
pub fn argon2_hash(password: String) -> crate::Result<String> {
    crate::map_cas_err(CASArgon::hash_password(password))
}

#[napi]
pub fn argon2_verify(hashed_password: String, password_to_verify: String) -> crate::Result<bool> {
    crate::map_cas_err(CASArgon::verify_password(hashed_password, password_to_verify))
}

#[napi]
pub fn argon2_hash_params(memory_cost: u32, iterations: u32, parallelism: u32, password: String, ) -> crate::Result<String> {
    crate::map_cas_err(CASArgon::hash_password_parameters(memory_cost, iterations, parallelism, password))
}

#[napi]
pub fn argon2_generate_salt() -> Vec<u8> {
    CASArgon::generate_salt()
}

#[napi]
pub fn argon2_derive_aes_128_key_with_salt(password: Vec<u8>, salt: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(CASArgon::derive_aes_128_key_with_salt(password, salt))
}

#[napi]
pub fn argon2_derive_aes_256_key_with_salt(password: Vec<u8>, salt: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(CASArgon::derive_aes_256_key_with_salt(password, salt))
}

#[napi]
#[allow(deprecated)]
pub fn argon2_derive_aes_128_key(password: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(CASArgon::derive_aes_128_key(password))
}

#[napi]
#[allow(deprecated)]
pub fn argon2_derive_aes_256_key(password: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(CASArgon::derive_aes_256_key(password))
}

#[test]
pub fn argon2_hash_params_test() {
    let password = crate::test_util::random_password();
    let hashed = argon2_hash_params(19, 2, 1, password.clone()).unwrap();
    assert!(hashed.contains("$m=19456,t=2,p=1$"));
    assert_eq!(true, argon2_verify(hashed, password).unwrap());
}

#[test]
pub fn argon2_hash_params_bounds_test() {
    let password = crate::test_util::random_password();
    assert!(argon2_hash_params(18, 2, 1, password.clone()).is_err());
    assert!(argon2_hash_params(4097, 2, 1, password.clone()).is_err());
    assert!(argon2_hash_params(4_194_305, 2, 1, password.clone()).is_err());
    assert!(argon2_hash_params(19, 0, 1, password.clone()).is_err());
    assert!(argon2_hash_params(19, 11, 1, password.clone()).is_err());
    assert!(argon2_hash_params(19, 2, 0, password.clone()).is_err());
    assert!(argon2_hash_params(19, 2, 17, password.clone()).is_err());
    assert!(argon2_hash_params(19, 10, 1, password.clone()).is_ok());
    assert!(argon2_hash_params(19, 1, 16, password).is_ok());
}

#[cfg(test)]
const ARGON2_256_KIB_HASH: &str = "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";

#[test]
pub fn argon2_verify_below_minimum_cost_test() {
    assert_eq!(true, argon2_verify(ARGON2_256_KIB_HASH.to_string(), "password".to_string()).unwrap());
}

#[test]
pub fn argon2_verify_refuses_hostile_hash_test() {
    for params in ["m=4194305,t=2,p=1", "m=256,t=11,p=1", "m=256,t=2,p=17"] {
        let hostile = ARGON2_256_KIB_HASH.replace("m=256,t=2,p=1", params);
        assert!(argon2_verify(hostile, "password".to_string()).is_err());
    }
}

#[test]
pub fn argon2_hash_test() {
    let password = crate::test_util::random_password();
    let hashed = argon2_hash(password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_verify_test() {
    let password = crate::test_util::random_password();
    let hashed = argon2_hash(password.clone()).unwrap();
    let verified = argon2_verify(hashed, password).unwrap();
    assert_eq!(true, verified);
}

#[test]
pub fn argon2_derive_aes_128_key_test() {
    let password = crate::test_util::random_password().into_bytes();
    let key = argon2_derive_aes_128_key(password.clone()).unwrap();
    assert_eq!(key.len(), 16);
    // A random salt is generated per call, so the same password must not repeat a key.
    let second_key = argon2_derive_aes_128_key(password).unwrap();
    assert_ne!(key, second_key);
}

#[test]
pub fn argon2_derive_aes_256_key_test() {
    let password = crate::test_util::random_password().into_bytes();
    let key = argon2_derive_aes_256_key(password.clone()).unwrap();
    assert_eq!(key.len(), 32);
    let second_key = argon2_derive_aes_256_key(password).unwrap();
    assert_ne!(key, second_key);
}

#[test]
pub fn argon2_generate_salt_test() {
    let salt = argon2_generate_salt();
    assert_eq!(salt.len(), 16);
    assert_ne!(salt, argon2_generate_salt());
}

#[test]
pub fn argon2_derive_aes_128_key_with_salt_test() {
    let password = crate::test_util::random_password().into_bytes();
    let salt = argon2_generate_salt();
    let key = argon2_derive_aes_128_key_with_salt(password.clone(), salt.clone()).unwrap();
    assert_eq!(key.len(), 16);
    assert_eq!(key, argon2_derive_aes_128_key_with_salt(password.clone(), salt).unwrap());
    assert_ne!(key, argon2_derive_aes_128_key_with_salt(password, argon2_generate_salt()).unwrap());
}

#[test]
pub fn argon2_derive_aes_256_key_with_salt_test() {
    let password = crate::test_util::random_password().into_bytes();
    let salt = argon2_generate_salt();
    let key = argon2_derive_aes_256_key_with_salt(password.clone(), salt.clone()).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(key, argon2_derive_aes_256_key_with_salt(password.clone(), salt).unwrap());
    assert_ne!(key, argon2_derive_aes_256_key_with_salt(password, argon2_generate_salt()).unwrap());
}

#[test]
pub fn argon2_derive_aes_key_with_short_salt_test() {
    let password = crate::test_util::random_password().into_bytes();
    assert!(argon2_derive_aes_128_key_with_salt(password.clone(), vec![0u8; 15]).is_err());
    assert!(argon2_derive_aes_256_key_with_salt(password.clone(), vec![0u8; 15]).is_err());
    assert!(argon2_derive_aes_256_key_with_salt(password, vec![0u8; 16]).is_ok());
}

#[test]
pub fn argon2_derive_aes_256_key_encrypt_decrypt_test() {
    use crate::symmetric::aes::{aes256_decrypt, aes256_encrypt, aes_nonce};
    let key = argon2_derive_aes_256_key_with_salt(crate::test_util::random_password().into_bytes(), argon2_generate_salt()).unwrap();
    let nonce = aes_nonce();
    let plaintext = b"WelcomeHome".to_vec();
    let ciphertext = aes256_encrypt(key.clone(), nonce.clone(), plaintext.clone()).unwrap();
    let decrypted_plaintext = aes256_decrypt(key, nonce, ciphertext).unwrap();
    assert_eq!(decrypted_plaintext, plaintext)
}

#[test]
pub fn argon2_verify_fail_test() {
    let password = crate::test_util::random_password();
    let hashed = argon2_hash(password.clone()).unwrap();
    let verified = crate::test_util::random_password();
    let verified = argon2_verify(hashed, verified).unwrap();
    assert_eq!(false, verified);
}
