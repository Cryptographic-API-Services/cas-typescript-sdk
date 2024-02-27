use napi_derive::napi;

#[napi(constructor)]
pub struct CASRSADigitalSignatureResult {
    pub public_key: String,
    pub private_key: String,
    pub signature: Vec<u8>,
}

pub trait CASDigitalSignature {
    fn digital_signature_rsa(
        rsa_key_size: u32,
        data_to_sign: Vec<u8>,
    ) -> CASRSADigitalSignatureResult;
    fn verify_rsa(public_key: String, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool;
}
