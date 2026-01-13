
use napi_derive::napi;
use cas_lib::password_hashers::argon2::CASArgon;

#[napi]
pub fn argon2_hash(password: String) -> String {
    return CASArgon::hash_password(password);
}

#[napi]
pub fn argon2_verify(hashed_password: String, password_to_verify: String) -> bool {
    return CASArgon::verify_password(hashed_password, password_to_verify);
}

#[napi]
pub fn argon2_hash_params(memory_cost: u32, iterations: u32, parallelism: u32, password: String, ) -> String {
    return CASArgon::hash_password_parameters(memory_cost, iterations, parallelism, password);
}

#[test]
pub fn argon2_hash_params_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash_params(1024, 2, 1, password.clone());
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_hash_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone());
    assert_ne!(password, hashed);
}

#[test]
pub fn argon2_verify_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone());
    let verified = argon2_verify(hashed, password);
    assert_eq!(true, verified);
}

#[test]
pub fn argon2_verify_fail_test() {
    let password = "ThisIsNotMyPasswolrd".to_string();
    let hashed = argon2_hash(password.clone());
    let verified = "Nope".to_string();
    let verified = argon2_verify(hashed, verified);
    assert_eq!(false, verified);
}
