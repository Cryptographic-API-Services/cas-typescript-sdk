use cas_lib::password_hashers::cas_password_hasher::Pbkdf2Result;
use cas_lib::password_hashers::pbkdf2::{derivation, derivation_with_salt};
use napi_derive::napi;

#[napi(constructor)]
pub struct CASPbkdf2Result {
    pub derived_key: Vec<u8>,
    pub salt: Vec<u8>,
}

impl From<Pbkdf2Result> for CASPbkdf2Result {
    fn from(result: Pbkdf2Result) -> Self {
        CASPbkdf2Result {
            derived_key: result.password,
            salt: result.salt,
        }
    }
}

#[napi]
pub fn pbkdf2_derive(password: Vec<u8>, number_of_iterations: u32) -> CASPbkdf2Result {
    return derivation(password, number_of_iterations).into();
}

#[napi]
pub fn pbkdf2_derive_with_salt(password: Vec<u8>, number_of_iterations: u32, salt: Vec<u8>) -> Vec<u8> {
    return derivation_with_salt(password, number_of_iterations, salt);
}

#[test]
fn pbkdf2_derive_with_salt_is_deterministic_test() {
    let password = b"BadPassword".to_vec();
    let salt = b"SixteenByteSalt!".to_vec();
    let key1 = pbkdf2_derive_with_salt(password.clone(), 1000, salt.clone());
    let key2 = pbkdf2_derive_with_salt(password, 1000, salt);
    assert_eq!(key1.len(), 32);
    assert_eq!(key1, key2);
}

#[test]
fn pbkdf2_derive_returned_salt_reproduces_key_test() {
    let password = b"BadPassword".to_vec();
    let result = pbkdf2_derive(password.clone(), 1000);
    let rederived = pbkdf2_derive_with_salt(password, 1000, result.salt);
    assert_eq!(result.derived_key, rederived);
}
