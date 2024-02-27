use napi_derive::napi;

#[napi(constructor)]
pub struct CASRSADigitalSignatureResult {
    pub public_key: String,
    pub private_key: String,
    pub signature: Vec<u8>,
}

#[napi(constructor)]
pub struct CASSHAED25519DalekDigitalSignatureResult {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>
}

pub trait CASRSADigitalSignature {
    fn digital_signature_rsa(
        rsa_key_size: u32,
        data_to_sign: Vec<u8>,
    ) -> CASRSADigitalSignatureResult;
    fn verify_rsa(public_key: String, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool;
}

pub trait CASED25519DigitalSignature {
    fn digital_signature_ed25519(data_to_sign: Vec<u8>) -> CASSHAED25519DalekDigitalSignatureResult;
    fn digital_signature_ed25519_verify(public_key: Vec<u8>, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool;
}