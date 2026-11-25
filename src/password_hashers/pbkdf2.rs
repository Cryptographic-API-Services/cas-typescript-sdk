use cas_lib::password_hashers::cas_password_hasher::Pbkdf2Result;
use cas_lib::password_hashers::pbkdf2::{derivation, derivation_with_salt};
use napi_derive::napi;

#[napi(object, js_name = "CASPbkdf2Result")]
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
pub fn pbkdf2_derive(password: Vec<u8>, number_of_iterations: u32) -> crate::Result<CASPbkdf2Result> {
    crate::map_cas_err(derivation(password, number_of_iterations)).map(Into::into)
}

#[napi]
pub fn pbkdf2_derive_with_salt(password: Vec<u8>, number_of_iterations: u32, salt: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(derivation_with_salt(password, number_of_iterations, salt))
}

#[cfg(test)]
use cas_lib::password_hashers::pbkdf2::{MIN_ITERATIONS, MIN_SALT_LENGTH};

#[cfg(test)]
fn random_salt(length: usize) -> Vec<u8> {
    let mut salt = crate::symmetric::aes::aes256_key();
    salt.truncate(length);
    salt
}

#[test]
fn pbkdf2_derive_with_salt_is_deterministic_test() {
    let password = crate::test_util::random_password().into_bytes();
    let salt = random_salt(MIN_SALT_LENGTH);
    let key1 = pbkdf2_derive_with_salt(password.clone(), MIN_ITERATIONS, salt.clone()).unwrap();
    let key2 = pbkdf2_derive_with_salt(password, MIN_ITERATIONS, salt).unwrap();
    assert_eq!(key1.len(), 32);
    assert_eq!(key1, key2);
}

#[test]
fn pbkdf2_derive_returned_salt_reproduces_key_test() {
    let password = crate::test_util::random_password().into_bytes();
    let result = pbkdf2_derive(password.clone(), MIN_ITERATIONS).unwrap();
    let rederived = pbkdf2_derive_with_salt(password, MIN_ITERATIONS, result.salt).unwrap();
    assert_eq!(result.derived_key, rederived);
}

#[test]
fn pbkdf2_rejects_too_few_iterations_test() {
    let password = crate::test_util::random_password().into_bytes();
    let salt = random_salt(MIN_SALT_LENGTH);
    assert!(pbkdf2_derive(password.clone(), MIN_ITERATIONS - 1).is_err());
    assert!(pbkdf2_derive_with_salt(password, MIN_ITERATIONS - 1, salt).is_err());
}

#[test]
fn pbkdf2_rejects_short_salt_test() {
    let password = crate::test_util::random_password().into_bytes();
    let salt = random_salt(MIN_SALT_LENGTH - 1);
    assert!(pbkdf2_derive_with_salt(password, MIN_ITERATIONS, salt).is_err());
}
