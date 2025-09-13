use cas_lib::password_hashers::bcrypt::CASBCrypt;
use cas_lib::password_hashers::cas_password_hasher::CASPasswordHasher;
use napi_derive::napi;

#[napi]
pub fn bcrypt_hash(password_to_hash: String) -> String {
    return <CASBCrypt as CASPasswordHasher>::hash_password(password_to_hash);
}

#[napi]
pub fn bcrypt_verify(hashed_password: String, password_to_verify: String) -> bool {
    return <CASBCrypt as CASPasswordHasher>::verify_password(hashed_password, password_to_verify);
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
