use cas_lib::hashers::{blake2::CASBlake2, cas_hasher::CASHasher, sha::CASSHA};
use napi_derive::napi;

#[napi]
pub fn blake2_sha_512(data_to_hash: Vec<u8>) -> Vec<u8> {
    return CASBlake2::hash_512(data_to_hash);
}

#[napi]
pub fn blake2_sha_512_verify(data_to_hash: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
    return CASBlake2::verify_512(data_to_hash, data_to_verify);
}

#[napi]
pub fn blake2_sha_256(data_to_hash: Vec<u8>) -> Vec<u8> {
    return CASBlake2::hash_256(data_to_hash);
}

#[napi]
pub fn blake2_sha_256_verify(data_to_hash: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
    return CASBlake2::verify_256(data_to_hash, data_to_verify);
}

#[test]
pub fn blake2_sha_512_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let hashed_data = blake2_sha_512(data_to_hash.clone());
    assert_ne!(true, hashed_data.eq(&data_to_hash));
}

#[test]
pub fn blake2_sha_512_verify_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let hashed_data = blake2_sha_512(data_to_hash.clone());
    let data_to_verify = "NotMyDataToHash".as_bytes().to_vec();
    assert_ne!(true, blake2_sha_512_verify(data_to_hash, data_to_verify));
}

#[test]
pub fn blake2_sha_512_verify_fail_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = blake2_sha_512(data_to_hash.clone());
    let data_to_verify = "NotMyDataToHash2".as_bytes().to_vec();
    assert_ne!(true, blake2_sha_512_verify(data_to_hash, data_to_verify));
}

#[test]
pub fn blake2_sha_256_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let hashed_data = blake2_sha_256(data_to_hash.clone());
    assert_ne!(true, hashed_data.eq(&data_to_hash));
}

#[test]
pub fn blake2_sha_256_verify_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = blake2_sha_256(data_to_hash.clone());
    let data_to_verify = "NotMyDataToHash".as_bytes().to_vec();
    assert_ne!(true, blake2_sha_256_verify(data_to_hash, data_to_verify));
}

#[test]
pub fn blake2_sha_256_verify_fail_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = blake2_sha_256(data_to_hash.clone());
    let data_to_verify = "NotMyDataToHash2".as_bytes().to_vec();
    assert_ne!(true, blake2_sha_256_verify(data_to_hash, data_to_verify));
}
