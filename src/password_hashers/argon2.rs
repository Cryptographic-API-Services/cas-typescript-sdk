
use napi_derive::napi;
use cas_lib::password_hashers::argon2::CASArgon;

#[napi]
pub fn argon2_hash(password: String) -> napi::Result<String> {
    crate::map_cas_err(CASArgon::hash_password(password))
}

#[napi]
pub fn argon2_verify(hashed_password: String, password_to_verify: String) -> napi::Result<bool> {
    crate::map_cas_err(CASArgon::verify_password(hashed_password, password_to_verify))
}

#[napi]
pub fn argon2_hash_params(memory_cost: u32, iterations: u32, parallelism: u32, password: String, ) -> napi::Result<String> {
    crate::map_cas_err(CASArgon::hash_password_parameters(memory_cost, iterations, parallelism, password))
}

#[test]
pub fn argon2_hash_params_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash_params(1024, 2, 1, password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_hash_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone()).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_verify_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone()).unwrap();
    let verified = argon2_verify(hashed, password).unwrap();
    assert_eq!(true, verified);
}

#[test]
pub fn argon2_verify_fail_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone()).unwrap();
    let verified = "Nope".to_string();
    let verified = argon2_verify(hashed, verified).unwrap();
    assert_eq!(false, verified);
}
