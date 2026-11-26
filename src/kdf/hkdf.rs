use cas_lib::kdf::cas_hkdf::{CASHkdfSha256, CASHkdfSha512, CASHKDF};
use napi_derive::napi;

#[napi]
pub fn hkdf_sha256_extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
    <CASHkdfSha256 as CASHKDF>::extract(salt, ikm)
}

#[napi]
pub fn hkdf_sha256_expand(prk: Vec<u8>, info: Vec<u8>, length: u32) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASHkdfSha256 as CASHKDF>::expand(prk, info, length as usize))
}

#[napi]
pub fn hkdf_sha256_derive(
    salt: Vec<u8>,
    ikm: Vec<u8>,
    info: Vec<u8>,
    length: u32,
) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASHkdfSha256 as CASHKDF>::derive(salt, ikm, info, length as usize))
}

#[napi]
pub fn hkdf_sha512_extract(salt: Vec<u8>, ikm: Vec<u8>) -> Vec<u8> {
    <CASHkdfSha512 as CASHKDF>::extract(salt, ikm)
}

#[napi]
pub fn hkdf_sha512_expand(prk: Vec<u8>, info: Vec<u8>, length: u32) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASHkdfSha512 as CASHKDF>::expand(prk, info, length as usize))
}

#[napi]
pub fn hkdf_sha512_derive(
    salt: Vec<u8>,
    ikm: Vec<u8>,
    info: Vec<u8>,
    length: u32,
) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASHkdfSha512 as CASHKDF>::derive(salt, ikm, info, length as usize))
}

#[cfg(test)]
use crate::test_util::random_bytes;

// Known answers come from the Wycheproof files in tests/wycheproof-hkdf.spec.ts.
#[test]
fn hkdf_extract_then_expand_matches_derive_test() {
    let salt = random_bytes(64);
    let ikm = random_bytes(96);
    let prk = hkdf_sha512_extract(salt.clone(), ikm.clone());
    assert_eq!(64, prk.len());
    let send = hkdf_sha512_expand(prk.clone(), b"send".to_vec(), 32).unwrap();
    let receive = hkdf_sha512_expand(prk, b"receive".to_vec(), 32).unwrap();
    assert_ne!(send, receive);
    assert_eq!(send, hkdf_sha512_derive(salt.clone(), ikm.clone(), b"send".to_vec(), 32).unwrap());

    let prk = hkdf_sha256_extract(salt.clone(), ikm.clone());
    assert_eq!(32, prk.len());
    let okm = hkdf_sha256_expand(prk, b"send".to_vec(), 42).unwrap();
    assert_eq!(okm, hkdf_sha256_derive(salt, ikm, b"send".to_vec(), 42).unwrap());
}

#[test]
fn hkdf_rejects_bad_lengths_and_short_prk_test() {
    let code = |result: crate::Result<Vec<u8>>| result.unwrap_err().status.as_ref().to_string();
    let ikm = random_bytes(32);
    assert_eq!("CAS_INVALID_PARAMETERS", code(hkdf_sha256_expand(random_bytes(32), vec![], 0)));
    assert_eq!("CAS_INVALID_PARAMETERS", code(hkdf_sha256_derive(vec![], ikm.clone(), vec![], 255 * 32 + 1)));
    assert_eq!("CAS_INVALID_PARAMETERS", code(hkdf_sha512_derive(vec![], ikm, vec![], 255 * 64 + 1)));
    assert_eq!("CAS_INVALID_KEY", code(hkdf_sha512_expand(random_bytes(63), vec![], 32)));
    assert_eq!(255 * 64, hkdf_sha512_expand(random_bytes(64), vec![], 255 * 64).unwrap().len());
}
