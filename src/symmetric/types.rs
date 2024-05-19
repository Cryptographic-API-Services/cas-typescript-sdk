use cas_lib::symmetric::cas_symmetric_encryption::AesKeyFromX25519SharedSecret;
use napi_derive::napi;

#[napi(constructor)]
pub struct CASAesKeyFromX25519SharedSecret {
    pub aes_key: Vec<u8>,
    pub aes_nonce: Vec<u8>,
}

impl From<AesKeyFromX25519SharedSecret> for CASAesKeyFromX25519SharedSecret {
    fn from(value: AesKeyFromX25519SharedSecret) -> Self {
        CASAesKeyFromX25519SharedSecret {
            aes_key: value.aes_key,
            aes_nonce: value.aes_nonce
        }
    }
}