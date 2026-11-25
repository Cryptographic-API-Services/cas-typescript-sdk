use cas_lib::password_hashers::{scrypt::CASScrypt};
use napi_derive::napi;

#[napi]
pub fn scrypt_hash(password_to_hash: String) -> crate::Result<String> {
    crate::map_cas_err(CASScrypt::hash_password(password_to_hash))
}

#[napi]
pub fn scrypt_verify(hashed_password: String, password_to_verify: String) -> crate::Result<bool> {
    crate::map_cas_err(CASScrypt::verify_password(hashed_password, password_to_verify))
}

#[napi]
pub fn scrypt_hash_params(password: String, cpu_memory_cost: u8, block_size: u32, parallelism: u32) -> crate::Result<String> {
    crate::map_cas_err(CASScrypt::hash_password_customized(password, cpu_memory_cost, block_size, parallelism))
}

#[test]
pub fn scrypt_hash_params_test() {
    let password = crate::test_util::random_password();
    let hashed = scrypt_hash_params(password.clone(), 15, 8, 1).unwrap();
    assert_ne!(password, hashed);
}

#[test]
pub fn scrypt_hash_params_bounds_test() {
    let password = crate::test_util::random_password();
    assert!(scrypt_hash_params(password.clone(), 9, 8, 1).is_err());
    assert!(scrypt_hash_params(password.clone(), 21, 8, 1).is_err());
    assert!(scrypt_hash_params(password.clone(), 10, 0, 1).is_err());
    assert!(scrypt_hash_params(password.clone(), 10, 33, 1).is_err());
    assert!(scrypt_hash_params(password.clone(), 10, 8, 0).is_err());
    assert!(scrypt_hash_params(password.clone(), 10, 8, 17).is_err());
    assert!(scrypt_hash_params(password.clone(), 10, 32, 1).is_ok());
    assert!(scrypt_hash_params(password, 10, 1, 16).is_ok());
}

#[cfg(test)]
const SCRYPT_LOG_N_8_HASH: &str = "$scrypt$ln=8,r=8,p=1$Y2FzLXNkay1zY3J5cHQtbG44$we6PL3qFpfGm2MUwKWwoMg8sO/qJYxFio5fRYVWizCk";

#[test]
pub fn scrypt_verify_below_minimum_cost_test() {
    assert_eq!(true, scrypt_verify(SCRYPT_LOG_N_8_HASH.to_string(), "password".to_string()).unwrap());
}

#[test]
pub fn scrypt_verify_refuses_hostile_hash_test() {
    for params in ["ln=21,r=8,p=1", "ln=8,r=33,p=1", "ln=8,r=8,p=17"] {
        let hostile = SCRYPT_LOG_N_8_HASH.replace("ln=8,r=8,p=1", params);
        assert!(scrypt_verify(hostile, "password".to_string()).is_err());
    }
}

#[test]
pub fn scrypt_hash_test() {
    let password = crate::test_util::random_password();
    let hashed_password = scrypt_hash(password.clone()).unwrap();
    assert_ne!(password, hashed_password);
}

#[test]
pub fn scrypt_verify_test() {
    let password = crate::test_util::random_password();
    let hashed_password = scrypt_hash(password.clone()).unwrap();
    let verified = scrypt_verify(hashed_password, password).unwrap();
    assert_eq!(true, verified);
}

#[test]
pub fn scrypt_verify_fail_test() {
    let password = crate::test_util::random_password();
    let hashed_password = scrypt_hash(password.clone()).unwrap();
    let verified = crate::test_util::random_password();
    let verified = scrypt_verify(hashed_password, verified).unwrap();
    assert_eq!(false, verified);
}
