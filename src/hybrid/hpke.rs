use crate::hybrid::types::{HpkeEncryptResult, HpkeKeyResult};
use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi]
pub fn hpke_generate_keypair() -> HpkeKeyResult {
    let (secret_key, public_key, info_str) = <CASHPKE as CASHybrid>::generate_key_pair();
    HpkeKeyResult {
        public_key: public_key.into(),
        secret_key: secret_key.into(),
        info_str: info_str.into()
    }
}

#[napi]
pub fn generate_info_str() -> Uint8Array {
    return <CASHPKE as CASHybrid>::generate_info_str().into();
}

#[napi]
pub fn hpke_encrypt(
    plaintext: Uint8Array,
    public_key: Uint8Array,
    info_str: Uint8Array,
) -> napi::Result<HpkeEncryptResult> {
    let encrypt_result: (Vec<u8>, Vec<u8>, Vec<u8>) =
        crate::map_cas_err(<CASHPKE as CASHybrid>::encrypt(plaintext.to_vec(), public_key.to_vec(), info_str.to_vec()))?;
    Ok(HpkeEncryptResult {
        tag: encrypt_result.2.into(),
        ciphertext: encrypt_result.1.into(),
        encapsulated_key: encrypt_result.0.into(),
    })
}

#[napi]
pub fn hpke_decrypt(
    ciphertext: Uint8Array,
    private_key: Uint8Array,
    encapped_key: Uint8Array,
    tag: Uint8Array,
    info_str: Uint8Array,
) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<CASHPKE as CASHybrid>::decrypt(ciphertext.to_vec(), private_key.to_vec(), encapped_key.to_vec(), tag.to_vec(), info_str.to_vec()))
        .map(Uint8Array::from)
}

#[test]
pub fn hpke_encrypt_decrypt_test() {
    let hpke_keypair = hpke_generate_keypair();
    let plaintext = "This is a secret message".as_bytes().to_vec();
    // info_str is needed for both encrypt and decrypt; Uint8Array isn't Clone,
    // so hold it as Vec<u8> and build a fresh view for each call.
    let info_str = hpke_keypair.info_str.to_vec();
    let encrypt_result = hpke_encrypt(
        plaintext.clone().into(),
        hpke_keypair.public_key,
        info_str.clone().into(),
    ).unwrap();
    let decrypted_plaintext = hpke_decrypt(
        encrypt_result.ciphertext,
        hpke_keypair.secret_key,
        encrypt_result.encapsulated_key,
        encrypt_result.tag,
        info_str.into(),
    ).unwrap();
    assert_eq!(plaintext, decrypted_plaintext.to_vec());
}

#[test]
pub fn generate_info_str_test() {
    let info_str = generate_info_str();
    assert_eq!(false, info_str.is_empty());
}
