
use cas_lib::symmetric::cas_symmetric_encryption::{Aes128KeyFromX25519SharedSecret, Aes256KeyFromX25519SharedSecret};
use napi_derive::napi;

#[napi(constructor)]
pub struct CASAesKeyFromX25519SharedSecret {
    pub aes_key: Vec<u8>,
    pub aes_nonce: Vec<u8>,
}

impl From<Aes128KeyFromX25519SharedSecret> for CASAesKeyFromX25519SharedSecret {
    fn from(value: Aes128KeyFromX25519SharedSecret) -> Self {
        CASAesKeyFromX25519SharedSecret {
            aes_key: value.aes_key.to_vec(),
            aes_nonce: value.aes_nonce.to_vec()
        }
    }
}

impl From<Aes256KeyFromX25519SharedSecret> for CASAesKeyFromX25519SharedSecret {
    fn from(value: Aes256KeyFromX25519SharedSecret) -> Self {
        CASAesKeyFromX25519SharedSecret {
            aes_key: value.aes_key.to_vec(),
            aes_nonce: value.aes_nonce.to_vec()
        }
    }
}