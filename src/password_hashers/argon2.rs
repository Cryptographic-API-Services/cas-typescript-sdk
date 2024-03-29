use std::net::ToSocketAddrs;

use napi_derive::napi;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};

use super::cas_password_hasher::CASPasswordHasher;

pub struct CASArgon;

impl CASPasswordHasher for CASArgon {
    fn hash_password(password_to_hash: String) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hashed_password = argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .unwrap()
            .to_string();
        return hashed_password;
    }

    fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        let hashed_password = PasswordHash::new(&hashed_password).unwrap();
        return Argon2::default()
            .verify_password(password_to_verify.as_bytes(), &hashed_password)
            .is_ok();
    }
}

#[napi]
pub fn argon2_hash(password: String) -> String {
    return <CASArgon as CASPasswordHasher>::hash_password(password);
}

#[napi]
pub fn argon2_verify(hashed_password: String, password_to_verify: String) -> bool {
    return <CASArgon as CASPasswordHasher>::verify_password(hashed_password, password_to_verify);
}

#[test]
pub fn argon2_hash_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone());
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_verify_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone());
    let verified = argon2_verify(hashed, password);
    assert_eq!(true, verified);
}

#[test]
pub fn argon2_verify_fail_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone());
    let verified = "Nope".to_string();
    let verified = argon2_verify(hashed, verified);
    assert_eq!(false, verified);
}
