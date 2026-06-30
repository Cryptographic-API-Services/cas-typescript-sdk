use cas_lib::hashers::{blake2::CASBlake2, cas_hasher::CASHasher};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi]
pub fn blake2_sha_512(data_to_hash: Uint8Array) -> Uint8Array {
    return CASBlake2::hash_512(data_to_hash.to_vec()).into();
}

#[napi]
pub fn blake2_sha_512_verify(data_to_hash: Uint8Array, data_to_verify: Uint8Array) -> bool {
    return CASBlake2::verify_512(data_to_hash.to_vec(), data_to_verify.to_vec());
}

#[napi]
pub fn blake2_sha_256(data_to_hash: Uint8Array) -> Uint8Array {
    return CASBlake2::hash_256(data_to_hash.to_vec()).into();
}

#[napi]
pub fn blake2_sha_256_verify(data_to_hash: Uint8Array, data_to_verify: Uint8Array) -> bool {
    return CASBlake2::verify_256(data_to_hash.to_vec(), data_to_verify.to_vec());
}

#[test]
pub fn blake2_sha_512_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let hashed_data = blake2_sha_512(data_to_hash.clone().into());
    assert_ne!(true, hashed_data.to_vec().eq(&data_to_hash));
}

#[test]
pub fn blake2_sha_512_verify_fail_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = blake2_sha_512(data_to_hash.clone().into());
    let data_to_verify = "NotMyDataToHash2".as_bytes().to_vec();
    assert_ne!(true, blake2_sha_512_verify(data_to_hash.into(), data_to_verify.into()));
}

#[test]
pub fn blake2_sha_256_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let hashed_data = blake2_sha_256(data_to_hash.clone().into());
    assert_ne!(true, hashed_data.to_vec().eq(&data_to_hash));
}

#[test]
pub fn blake2_sha_256_verify_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = blake2_sha_256(data_to_hash.clone().into());
    let data_to_verify = "NotMyDataToHash".as_bytes().to_vec();
    assert_ne!(true, blake2_sha_256_verify(data_to_hash.into(), data_to_verify.into()));
}

#[test]
pub fn blake2_sha_256_verify_fail_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = blake2_sha_256(data_to_hash.clone().into());
    let data_to_verify = "NotMyDataToHash2".as_bytes().to_vec();
    assert_ne!(true, blake2_sha_256_verify(data_to_hash.into(), data_to_verify.into()));
}
