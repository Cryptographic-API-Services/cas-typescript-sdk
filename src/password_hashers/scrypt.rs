use cas_lib::password_hashers::{scrypt::CASScrypt};
use napi_derive::napi;

#[napi]
pub fn scrypt_hash(password_to_hash: String) -> String {
    return CASScrypt::hash_password(password_to_hash);
}

#[napi]
pub fn scrypt_verify(hashed_password: String, password_to_verify: String) -> bool {
    return CASScrypt::verify_password(hashed_password, password_to_verify);
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
