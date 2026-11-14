use cas_lib::hashers::{cas_hasher::CASHasher, sha::CASSHA};
use napi_derive::napi;

#[napi]
pub fn sha_512(data_to_hash: Vec<u8>) -> Vec<u8> {
    return <CASSHA as CASHasher>::hash_512(data_to_hash);
}

#[napi]
pub fn sha_512_verify(data_to_hash: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
    return <CASSHA as CASHasher>::verify_512(data_to_hash, data_to_verify);
}

#[napi]
pub fn sha_256(data_to_hash: Vec<u8>) -> Vec<u8> {
    return <CASSHA as CASHasher>::hash_256(data_to_hash);
}

#[napi]
pub fn sha_256_verify(data_to_hash: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
    return <CASSHA as CASHasher>::verify_256(data_to_hash, data_to_verify);
}

#[test]
pub fn sha_512_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let hashed_data = sha_512(data_to_hash.clone());
    assert_ne!(true, hashed_data.eq(&data_to_hash));
}

#[test]
pub fn sha_512_verify_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let data_to_verify = "NotMyDataToHash".as_bytes().to_vec();
    assert_ne!(true, sha_512_verify(data_to_hash, data_to_verify));
}

#[test]
pub fn sha_512_verify_fail_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = sha_512(data_to_hash.clone());
    let data_to_verify = "NotMyDataToHash2".as_bytes().to_vec();
    assert_ne!(true, sha_512_verify(data_to_hash, data_to_verify));
}

#[test]
pub fn sha_256_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let hashed_data = sha_256(data_to_hash.clone());
    assert_ne!(true, hashed_data.eq(&data_to_hash));
}

#[test]
pub fn sha_256_verify_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = sha_256(data_to_hash.clone());
    let data_to_verify = "NotMyDataToHash".as_bytes().to_vec();
    assert_ne!(true, sha_256_verify(data_to_hash, data_to_verify));
}

#[test]
pub fn sha_256_verify_fail_test() {
    let data_to_hash = "NotMyDataToHash".as_bytes().to_vec();
    let _hashed_data = sha_256(data_to_hash.clone());
    let data_to_verify = "NotMyDataToHash2".as_bytes().to_vec();
    assert_ne!(true, sha_256_verify(data_to_hash, data_to_verify));
}

#[cfg(test)]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// FIPS 202 known answers for the empty message: hashing "" is valid and has a
// well-defined digest (see cas-core-lib#81).
#[test]
pub fn sha_512_empty_input_test() {
    let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    let hash = sha_512(Vec::new());
    assert_eq!(expected, to_hex(&hash));
    assert_eq!(true, sha_512_verify(hash.clone(), Vec::new()));
    assert_eq!(false, sha_512_verify(hash, b"abc".to_vec()));
}

#[test]
pub fn sha_256_empty_input_test() {
    let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    let hash = sha_256(Vec::new());
    assert_eq!(expected, to_hex(&hash));
    assert_eq!(true, sha_256_verify(hash.clone(), Vec::new()));
    assert_eq!(false, sha_256_verify(hash, b"abc".to_vec()));
}
