use cas_lib::password_hashers::bcrypt::CASBCrypt;
use napi_derive::napi;

#[napi]
pub fn bcrypt_hash(password_to_hash: String) -> String {
    return CASBCrypt::hash_password(password_to_hash);
}

#[napi]
pub fn bcrypt_verify(hashed_password: String, password_to_verify: String) -> bool {
    return CASBCrypt::verify_password(hashed_password, password_to_verify);
}

#[napi]
pub fn bcrypt_hash_params(cost: u32, password: String) -> String {
    return CASBCrypt::hash_password_customized(password, cost);
}

#[test]
pub fn bcrypt_hash_params_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = bcrypt_hash_params(12, password.clone());  
    assert_ne!(password, hashed);
}

#[test]
pub fn bcrypt_hash_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = bcrypt_hash(password.clone());
    assert_ne!(password, hashed);
}

#[test]
pub fn bcrypt_verify_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = bcrypt_hash(password.clone());
    let verified = bcrypt_verify(hashed, password);
    assert_eq!(true, verified);
}

#[test]
pub fn bcrypt_verify_fail_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = bcrypt_hash(password.clone());
    let verified = "nope".to_string();
    let verified = bcrypt_verify(hashed, verified);
    assert_eq!(false, verified);
}
