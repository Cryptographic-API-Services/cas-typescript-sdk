use cas_lib::key_exchange::x25519::X25519SecretPublicKeyResult;
use napi_derive::napi;

#[napi(constructor)]
pub struct CASx25519SecretPublicKeyResult {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl From<X25519SecretPublicKeyResult> for CASx25519SecretPublicKeyResult {
    fn from(value: X25519SecretPublicKeyResult) -> Self {
        CASx25519SecretPublicKeyResult {
            public_key: value.public_key,
            secret_key: value.secret_key
        }
    }
}