use napi_derive::napi;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher, PasswordHash, PasswordVerifier,
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
        return Argon2::default().verify_password(password_to_verify.as_bytes(), &hashed_password).is_ok()
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