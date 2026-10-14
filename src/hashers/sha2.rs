use cas_lib::hashers::{cas_hasher::CASHasher, sha2::CASSHA2};
use napi_derive::napi;

#[napi]
pub fn sha2_hash_512(data_to_hash: Vec<u8>) -> Vec<u8> {
    return <CASSHA2 as CASHasher>::hash_512(data_to_hash);
}

#[napi]
pub fn sha2_hash_512_verify(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
    return <CASSHA2 as CASHasher>::verify_512(hash_to_verify, data_to_verify);
}

#[napi]
pub fn sha2_hash_256(data_to_hash: Vec<u8>) -> Vec<u8> {
    return <CASSHA2 as CASHasher>::hash_256(data_to_hash);
}

#[napi]
pub fn sha2_hash_256_verify(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
    return <CASSHA2 as CASHasher>::verify_256(hash_to_verify, data_to_verify);
}

#[test]
pub fn sha2_hash_512_known_answer_test() {
    // FIPS 180-4 example: SHA-512("abc")
    let hash = sha2_hash_512(b"abc".to_vec());
    let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    assert_eq!(64, hash.len());
    assert_eq!(expected, hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}

#[test]
pub fn sha2_hash_256_known_answer_test() {
    // FIPS 180-4 example: SHA-256("abc")
    let hash = sha2_hash_256(b"abc".to_vec());
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(32, hash.len());
    assert_eq!(expected, hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}

#[test]
pub fn sha2_hash_512_verify_test() {
    let data = b"NotMyDataToHash".to_vec();
    let hash = sha2_hash_512(data.clone());
    assert_eq!(true, sha2_hash_512_verify(hash, data));
}

#[test]
pub fn sha2_hash_512_verify_fail_test() {
    let hash = sha2_hash_512(b"NotMyDataToHash".to_vec());
    assert_eq!(false, sha2_hash_512_verify(hash, b"NotMyDataToHash2".to_vec()));
}

#[test]
pub fn sha2_hash_256_verify_test() {
    let data = b"NotMyDataToHash".to_vec();
    let hash = sha2_hash_256(data.clone());
    assert_eq!(true, sha2_hash_256_verify(hash, data));
}

#[test]
pub fn sha2_hash_256_verify_fail_test() {
    let hash = sha2_hash_256(b"NotMyDataToHash".to_vec());
    assert_eq!(false, sha2_hash_256_verify(hash, b"NotMyDataToHash2".to_vec()));
}
