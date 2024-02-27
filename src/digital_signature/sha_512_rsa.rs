use napi_derive::napi;
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::EncodePrivateKey,
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha3::{Digest, Sha3_512};
use super::cas_digital_signature_rsa::{CASRSADigitalSignatureResult, CASRSADigitalSignature};
pub struct SHA512RSADigitalSignature;

impl CASRSADigitalSignature for SHA512RSADigitalSignature {
    fn digital_signature_rsa(
        rsa_key_size: u32,
        data_to_sign: Vec<u8>,
    ) -> CASRSADigitalSignatureResult {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_sign);
        let sha_hasher_result = hasher.finalize();
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey =
            RsaPrivateKey::new(&mut rng, rsa_key_size as usize).expect("failed to generate a key");
        let public_key = private_key.to_public_key();
        let mut signed_data = private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &sha_hasher_result)
            .unwrap();
        let result = CASRSADigitalSignatureResult {
            private_key: private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
            public_key: public_key
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
            signature: signed_data,
        };
        result
    }

    fn verify_rsa(public_key: String, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
        let mut hasher = Sha3_512::new();
        hasher.update(data_to_verify);
        let sha_hasher_result = hasher.finalize();
        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
        let verified = public_key.verify(
            Pkcs1v15Sign::new_unprefixed(),
            &sha_hasher_result,
            &signature,
        );
        if verified.is_err() == false {
            return true;
        } else {
            return false;
        }
    }
}

#[napi]
pub fn sha_512_rsa_digital_signature(
    rsa_key_size: u32,
    data_to_sign: Vec<u8>,
) -> CASRSADigitalSignatureResult {
    return SHA512RSADigitalSignature::digital_signature_rsa(rsa_key_size, data_to_sign);
}

#[napi]
pub fn sha_512_rsa_verify_digital_signature(
    public_key: String,
    data_to_verify: Vec<u8>,
    signature: Vec<u8>,
) -> bool {
    return SHA512RSADigitalSignature::verify_rsa(public_key, data_to_verify, signature);
}

#[test]
fn sha_512_rsa_digital_signature_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: CASRSADigitalSignatureResult = SHA512RSADigitalSignature::digital_signature_rsa(key_size, data_to_sign.clone());
    let is_verified: bool = SHA512RSADigitalSignature::verify_rsa(signature_result.public_key, data_to_sign, signature_result.signature);
    assert_eq!(is_verified, true);
}

#[test]
fn sha_512_rsa_digital_signature_fail_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: CASRSADigitalSignatureResult = SHA512RSADigitalSignature::digital_signature_rsa(key_size, data_to_sign.clone());
    let new_data = b"NOtTheOriginalData".to_vec();
    let is_verified: bool = SHA512RSADigitalSignature::verify_rsa(signature_result.public_key, new_data, signature_result.signature);
    assert_eq!(is_verified, false);
}
