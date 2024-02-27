use super::cas_hasher::CASHasher;
use blake2::{Blake2b512, Blake2s256, Digest};

pub struct CASBlake2;

impl CASHasher for CASBlake2 {
    fn hash_512(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Blake2b512::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    fn verify_512(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Blake2b512::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }

    fn hash_256(data_to_hash: Vec<u8>) -> Vec<u8> {
        let mut hasher = Blake2s256::new();
        hasher.update(data_to_hash);
        let result = hasher.finalize();
        return result.to_vec();
    }

    fn verify_256(hash_to_verify: Vec<u8>, data_to_verify: Vec<u8>) -> bool {
        let mut hasher = Blake2s256::new();
        hasher.update(data_to_verify);
        let result = hasher.finalize();
        return hash_to_verify.eq(&result.to_vec());
    }
}

#[test]
fn hash_512_test() {}
