use napi_derive::napi;
use bcrypt::{hash, verify, DEFAULT_COST};

#[napi]
pub fn bcrypt_hash(password_to_hash: String) -> String {
    return hash(password_to_hash, DEFAULT_COST).unwrap();
}

#[napi]
pub fn bcrypt_verify(hashed_password: String, password_to_verify: String) -> bool {
    return verify(password_to_verify, &hashed_password).unwrap();
}