use napi::bindgen_prelude::Array;
use napi_derive::napi;

use super::cas_hasher::CASHasher;
use sha3::{Digest, Sha3_256, Sha3_512};
pub struct CASSHA;

impl CASHasher for CASSHA {
    fn hash_512(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    fn verify_512(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }

    fn hash_256(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    fn verify_256(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }
}

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