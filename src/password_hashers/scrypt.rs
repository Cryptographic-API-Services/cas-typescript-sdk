use napi_derive::napi;

use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};

use super::cas_password_hasher::CASPasswordHasher;

pub struct CASScrypt;

impl CASPasswordHasher for CASScrypt {
    fn hash_password(password_to_hash: String) -> String {
        let salt = SaltString::generate(&mut OsRng);
        return Scrypt
            .hash_password(password_to_hash.as_bytes(), &salt)
            .unwrap()
            .to_string();
    }

    fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        let parsed_hash = PasswordHash::new(&hashed_password).unwrap();
        return Scrypt
            .verify_password(password_to_verify.as_bytes(), &parsed_hash)
            .is_ok();
    }
}

#[napi]
pub fn scrypt_hash(password_to_hash: String) -> String {
    return <CASScrypt as CASPasswordHasher>::hash_password(password_to_hash);
}

#[napi]
pub fn scrypt_verify(hashed_password: String, password_to_verify: String) -> bool {
    return <CASScrypt as CASPasswordHasher>::verify_password(hashed_password, password_to_verify);
}

#[test]
pub fn scrypt_hash_test() {
    let password = "BadPassword".to_string();
    let hashed_password = scrypt_hash(password.clone());
    assert_ne!(password, hashed_password);
}

#[test]
pub fn scrypt_verify_test() {
    let password = "BadPassword".to_string();
    let hashed_password = scrypt_hash(password.clone());
    let verified = scrypt_verify(hashed_password, password);
    assert_eq!(true, verified);
}

#[test]
pub fn scrypt_verify_fail_test() {
    let password = "BadPassword".to_string();
    let hashed_password = scrypt_hash(password.clone());
    let verified = "Nope".to_string();
    let verified = scrypt_verify(hashed_password, verified);
    assert_eq!(false, verified);
}
