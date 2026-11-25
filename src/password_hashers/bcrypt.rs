use cas_lib::password_hashers::bcrypt::CASBCrypt;
use napi_derive::napi;

#[napi]
pub fn bcrypt_hash(password_to_hash: String) -> napi::Result<String> {
    crate::map_cas_err(CASBCrypt::hash_password(password_to_hash))
}

#[napi]
pub fn bcrypt_verify(hashed_password: String, password_to_verify: String) -> napi::Result<bool> {
    crate::map_cas_err(CASBCrypt::verify_password(hashed_password, password_to_verify))
}

#[napi]
pub fn bcrypt_hash_params(cost: u32, password: String) -> napi::Result<String> {
    crate::map_cas_err(CASBCrypt::hash_password_customized(password, cost))
}

#[test]
pub fn bcrypt_hash_params_test() {
    let password = crate::test_util::random_password();
    let hashed = bcrypt_hash_params(12, password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn bcrypt_hash_test() {
    let password = crate::test_util::random_password();
    let hashed = bcrypt_hash(password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn bcrypt_verify_test() {
    let password = crate::test_util::random_password();
    let hashed = bcrypt_hash(password.clone()).unwrap();
    let verified = bcrypt_verify(hashed, password).unwrap();
    assert_eq!(true, verified);
}

#[cfg(test)]
fn random_password_of_length(length: usize) -> String {
    let mut password = String::new();
    while password.len() < length {
        password.push_str(&crate::test_util::random_password());
    }
    password.truncate(length);
    password
}

#[test]
pub fn bcrypt_accepts_72_byte_password_test() {
    let password = random_password_of_length(72);
    let hashed = bcrypt_hash(password.clone()).unwrap();
    assert_eq!(true, bcrypt_verify(hashed, password).unwrap());
}

#[test]
pub fn bcrypt_rejects_73_byte_password_test() {
    let password = random_password_of_length(73);
    assert!(bcrypt_hash(password.clone()).is_err());
    assert!(bcrypt_hash_params(4, password.clone()).is_err());
    let hashed = bcrypt_hash(password[..72].to_string()).unwrap();
    assert!(bcrypt_verify(hashed, password).is_err());
}

#[test]
pub fn bcrypt_verify_fail_test() {
    let password = crate::test_util::random_password();
    let hashed = bcrypt_hash(password.clone()).unwrap();
    let verified = crate::test_util::random_password();
    let verified = bcrypt_verify(hashed, verified).unwrap();
    assert_eq!(false, verified);
}
