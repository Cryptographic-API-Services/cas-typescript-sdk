use cas_lib::digital_signature::cas_digital_signature_rsa::{RSADigitalSignatureResult, SHAED25519DalekDigitalSignatureResult};
use napi_derive::napi;

#[napi(constructor)]
pub struct CASSHAED25519DalekDigitalSignatureResult {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>
}

impl From<SHAED25519DalekDigitalSignatureResult> for CASSHAED25519DalekDigitalSignatureResult {
    fn from(value: SHAED25519DalekDigitalSignatureResult) -> Self {
        CASSHAED25519DalekDigitalSignatureResult {
            public_key: value.public_key.to_vec(),
            signature: value.signature.to_vec()
        }
    }
}

#[napi(constructor)]
pub struct CASRSADigitalSignatureResult {
    pub public_key: String,
    pub private_key: String,
    pub signature: Vec<u8>,
}

impl From<RSADigitalSignatureResult> for CASRSADigitalSignatureResult {
    fn from(value: RSADigitalSignatureResult) -> Self {
        CASRSADigitalSignatureResult {
            public_key: value.public_key,
            private_key: value.private_key,
            signature: value.signature
        }
    }
}