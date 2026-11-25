use cas_lib::password_hashers::bcrypt::{BCRYPT_MAX_PASSWORD_BYTES, CASBCrypt};
use napi_derive::napi;

#[napi]
pub fn bcrypt_hash(password_to_hash: String) -> crate::Result<String> {
    crate::map_cas_err(CASBCrypt::hash_password(password_to_hash))
}

#[napi]
pub fn bcrypt_verify(hashed_password: String, password_to_verify: String) -> crate::Result<bool> {
    crate::map_cas_err(CASBCrypt::verify_password(hashed_password, password_to_verify))
}

#[napi]
pub fn bcrypt_hash_params(cost: u32, password: String) -> crate::Result<String> {
    crate::map_cas_err(CASBCrypt::hash_password_customized(password, cost))
}

#[test]
pub fn bcrypt_hash_params_test() {
    let password = crate::test_util::random_password();
    let hashed = bcrypt_hash_params(12, password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn bcrypt_hash_params_bounds_test() {
    let password = crate::test_util::random_password();
    assert!(bcrypt_hash_params(9, password.clone()).is_err());
    assert!(bcrypt_hash_params(17, password.clone()).is_err());
    let hashed = bcrypt_hash_params(10, password.clone()).unwrap();
    assert_eq!(true, bcrypt_verify(hashed, password).unwrap());
}

#[cfg(test)]
const BCRYPT_COST_4_HASH: &str = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";

#[test]
pub fn bcrypt_verify_below_minimum_cost_test() {
    assert_eq!(true, bcrypt_verify(BCRYPT_COST_4_HASH.to_string(), "correctbatteryhorsestapler".to_string()).unwrap());
}

#[test]
pub fn bcrypt_verify_refuses_hostile_hash_test() {
    for cost in ["$17$", "$31$"] {
        let hostile = BCRYPT_COST_4_HASH.replace("$04$", cost);
        assert!(bcrypt_verify(hostile, "correctbatteryhorsestapler".to_string()).is_err());
    }
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
    let password = random_password_of_length(BCRYPT_MAX_PASSWORD_BYTES);
    let hashed = bcrypt_hash(password.clone()).unwrap();
    assert_eq!(true, bcrypt_verify(hashed, password).unwrap());
}

#[test]
pub fn bcrypt_rejects_73_byte_password_test() {
    // One random password past the limit. `MAX + 1` is a literal, and CodeQL
    // treats that literal as the password it flows into.
    let mut password = random_password_of_length(BCRYPT_MAX_PASSWORD_BYTES);
    password.push_str(&crate::test_util::random_password());
    assert!(password.len() > BCRYPT_MAX_PASSWORD_BYTES);
    assert!(bcrypt_hash(password.clone()).is_err());
    assert!(bcrypt_hash_params(10, password.clone()).is_err());
    let hashed = bcrypt_hash(password[..BCRYPT_MAX_PASSWORD_BYTES].to_string()).unwrap();
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
