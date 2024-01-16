use napi_derive::napi;
use bcrypt::{hash, verify, DEFAULT_COST};

use super::cas_password_hasher::CASPasswordHasher;

pub struct CASBCrypt;

impl CASPasswordHasher for CASBCrypt {
    fn hash_password(password_to_hash: String) -> String {
        return hash(password_to_hash, DEFAULT_COST).unwrap();
    }

    fn verify_password(hashed_password: String, password_to_verify: String) -> bool {
        return verify(password_to_verify, &hashed_password).unwrap();
    }
}


#[napi]
pub fn bcrypt_hash(password_to_hash: String) -> String {
    return <CASBCrypt as CASPasswordHasher>::hash_password(password_to_hash);
}

#[napi]
pub fn bcrypt_verify(hashed_password: String, password_to_verify: String) -> bool {
    return <CASBCrypt as CASPasswordHasher>::verify_password(hashed_password, password_to_verify);
}