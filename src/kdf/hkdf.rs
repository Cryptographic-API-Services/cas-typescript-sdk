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
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 5869 Appendix A, test case 1.
#[test]
fn hkdf_sha256_rfc5869_case_1_test() {
    let ikm = vec![0x0b; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let okm = hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    let prk = hkdf_sha256_extract(salt.clone(), ikm.clone());
    assert_eq!(prk, hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    assert_eq!(hkdf_sha256_expand(prk, info.clone(), 42).unwrap(), okm);
    assert_eq!(hkdf_sha256_derive(salt, ikm, info, 42).unwrap(), okm);
}

#[test]
fn hkdf_sha512_extract_then_expand_matches_derive_test() {
    let salt = vec![1u8; 64];
    let ikm = vec![2u8; 96];
    let prk = hkdf_sha512_extract(salt.clone(), ikm.clone());
    assert_eq!(64, prk.len());
    let send = hkdf_sha512_expand(prk.clone(), b"send".to_vec(), 32).unwrap();
    let receive = hkdf_sha512_expand(prk, b"receive".to_vec(), 32).unwrap();
    assert_ne!(send, receive);
    assert_eq!(send, hkdf_sha512_derive(salt, ikm, b"send".to_vec(), 32).unwrap());
}

#[test]
fn hkdf_rejects_bad_lengths_and_short_prk_test() {
    let code = |result: crate::Result<Vec<u8>>| result.unwrap_err().status.as_ref().to_string();
    assert_eq!("CAS_INVALID_PARAMETERS", code(hkdf_sha256_expand(vec![1; 32], vec![], 0)));
    assert_eq!("CAS_INVALID_PARAMETERS", code(hkdf_sha256_derive(vec![], vec![1], vec![], 255 * 32 + 1)));
    assert_eq!("CAS_INVALID_PARAMETERS", code(hkdf_sha512_derive(vec![], vec![1], vec![], 255 * 64 + 1)));
    assert_eq!("CAS_INVALID_KEY", code(hkdf_sha512_expand(vec![1; 63], vec![], 32)));
    assert_eq!(255 * 64, hkdf_sha512_expand(vec![1; 64], vec![], 255 * 64).unwrap().len());
}
