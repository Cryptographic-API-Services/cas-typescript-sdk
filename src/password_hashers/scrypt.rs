use napi_derive::napi;

use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};

#[napi]
pub fn scrypt_hash(password_to_hash: String) -> String {
    let salt = SaltString::generate(&mut OsRng);
    return Scrypt.hash_password(password_to_hash.as_bytes(), &salt).unwrap().to_string();
}

#[napi]
pub fn scrypt_verify(hashed_password: String, password_to_verify: String) -> bool {
    let parsed_hash = PasswordHash::new(&hashed_password).unwrap();
    return Scrypt.verify_password(password_to_verify.as_bytes(), &parsed_hash).is_ok();
}