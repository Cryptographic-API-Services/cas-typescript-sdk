use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use napi_derive::napi;
use sha3::{Digest, Sha3_256};

use super::cas_digital_signature_rsa::{
    ED25519DigitalSignature, SHAED25519DalekDigitalSignatureResult,
};

pub struct SHA256ED25519DigitalSignature;

impl ED25519DigitalSignature for SHA256ED25519DigitalSignature {
    fn digital_signature_ed25519(data_to_sign: Vec<u8>) -> SHAED25519DalekDigitalSignatureResult {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_sign);
        let sha_hasher_result = hasher.finalize();
        let mut csprng = rand_07::rngs::OsRng {};
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);

        let signature = keypair.sign(&sha_hasher_result);
        let signature_bytes = signature.to_bytes();
        let public_keypair_bytes = keypair.public.to_bytes();
        let result = SHAED25519DalekDigitalSignatureResult {
            public_key: public_keypair_bytes.to_vec(),
            signature: signature_bytes.to_vec(),
        };
        result
    }

    fn digital_signature_ed25519_verify(public_key: Vec<u8>, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data_to_verify);
        let sha_hasher_result = hasher.finalize();

        let public_key_parsed = ed25519_dalek::PublicKey::from_bytes(&public_key).unwrap();
        let signature_parsed = Signature::from_bytes(&signature).unwrap();
        return public_key_parsed
            .verify(&sha_hasher_result, &signature_parsed)
            .is_ok();
    }
}

#[napi]
pub fn sha_256_ed25519_digital_signature(data_to_sign: Vec<u8>) -> SHAED25519DalekDigitalSignatureResult {
    return SHA256ED25519DigitalSignature::digital_signature_ed25519(data_to_sign);
}

#[napi]
pub fn sha_256_ed25519_digital_signature_verify(public_key: Vec<u8>, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
    return SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(public_key, data_to_verify, signature)
}

#[test]
fn sha_256_ed25519_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: SHAED25519DalekDigitalSignatureResult = SHA256ED25519DigitalSignature::digital_signature_ed25519(data_to_sign.clone());
    let is_verified: bool = SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(signature_result.public_key, data_to_sign, signature_result.signature);
    assert_eq!(is_verified, true);
}

#[test]
fn sha_512_ed25519_test_fail() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: SHAED25519DalekDigitalSignatureResult = SHA256ED25519DigitalSignature::digital_signature_ed25519(data_to_sign.clone());
    let not_original_data = b"NOtTHoseBytes".to_vec();
    let is_verified: bool = SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(signature_result.public_key, not_original_data, signature_result.signature);
    assert_eq!(is_verified, false);
}