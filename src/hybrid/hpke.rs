use crate::hybrid::types::{HpkeEncryptResult, HpkeKeyResult};
use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use napi_derive::napi;

#[napi]
pub fn hpke_generate_keypair() -> HpkeKeyResult {
    let (secret_key, public_key, info_str) = <CASHPKE as CASHybrid>::generate_key_pair();
    HpkeKeyResult {
        public_key: public_key,
        secret_key: secret_key,
        info_str: info_str
    }
}

#[napi]
pub fn generate_info_str() -> Vec<u8> {
    return <CASHPKE as CASHybrid>::generate_info_str();
}

#[napi]
pub fn hpke_encrypt(
    plaintext: Vec<u8>,
    public_key: Vec<u8>,
    info_str: Vec<u8>,
    aad: Vec<u8>,
) -> crate::Result<HpkeEncryptResult> {
    let encrypt_result: (Vec<u8>, Vec<u8>, Vec<u8>) =
        crate::map_cas_err(<CASHPKE as CASHybrid>::encrypt(plaintext, public_key, info_str, aad))?;
    Ok(HpkeEncryptResult {
        tag: encrypt_result.2,
        ciphertext: encrypt_result.1,
        encapsulated_key: encrypt_result.0,
    })
}

#[napi]
pub fn hpke_decrypt(
    ciphertext: Vec<u8>,
    private_key: Vec<u8>,
    encapped_key: Vec<u8>,
    tag: Vec<u8>,
    info_str: Vec<u8>,
    aad: Vec<u8>,
) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASHPKE as CASHybrid>::decrypt(ciphertext, private_key, encapped_key, tag, info_str, aad))
}

#[test]
pub fn hpke_encrypt_decrypt_test() {
    let hpke_keypair = hpke_generate_keypair();
    let plaintext = "This is a secret message".as_bytes().to_vec();
    let encrypt_result = hpke_encrypt(
        plaintext.clone(),
        hpke_keypair.public_key,
        hpke_keypair.info_str.clone(),
        vec![],
    ).unwrap();
    let decrypted_plaintext = hpke_decrypt(
        encrypt_result.ciphertext,
        hpke_keypair.secret_key,
        encrypt_result.encapsulated_key,
        encrypt_result.tag,
        hpke_keypair.info_str,
        vec![],
    ).unwrap();
    assert_eq!(plaintext, decrypted_plaintext);
}

#[test]
pub fn hpke_encrypt_decrypt_with_aad_test() {
    let hpke_keypair = hpke_generate_keypair();
    let plaintext = "This is a secret message".as_bytes().to_vec();
    let aad = "header".as_bytes().to_vec();
    let encrypt_result = hpke_encrypt(
        plaintext.clone(),
        hpke_keypair.public_key,
        hpke_keypair.info_str.clone(),
        aad.clone(),
    ).unwrap();
    let decrypt = |aad: Vec<u8>| hpke_decrypt(
        encrypt_result.ciphertext.clone(),
        hpke_keypair.secret_key.clone(),
        encrypt_result.encapsulated_key.clone(),
        encrypt_result.tag.clone(),
        hpke_keypair.info_str.clone(),
        aad,
    );
    assert_eq!(plaintext, decrypt(aad).unwrap());
    assert!(decrypt("other header".as_bytes().to_vec()).is_err());
    assert!(decrypt(vec![]).is_err());
}

#[test]
pub fn hpke_info_longer_than_65530_bytes_is_invalid_input_test() {
    let hpke_keypair = hpke_generate_keypair();
    let plaintext = "This is a secret message".as_bytes().to_vec();
    let longest_info = vec![0x61; 65_530];
    let encrypt_result = hpke_encrypt(
        plaintext.clone(),
        hpke_keypair.public_key.clone(),
        longest_info.clone(),
        vec![],
    ).unwrap();
    let decrypt = |info: Vec<u8>| hpke_decrypt(
        encrypt_result.ciphertext.clone(),
        hpke_keypair.secret_key.clone(),
        encrypt_result.encapsulated_key.clone(),
        encrypt_result.tag.clone(),
        info,
        vec![],
    );
    assert_eq!(plaintext, decrypt(longest_info).unwrap());

    let too_long_info = vec![0x61; 65_531];
    let encrypt_err = hpke_encrypt(plaintext, hpke_keypair.public_key, too_long_info.clone(), vec![])
        .err()
        .unwrap();
    assert_eq!("CAS_INVALID_INPUT", encrypt_err.status.as_ref());
    assert_eq!("CAS_INVALID_INPUT", decrypt(too_long_info).unwrap_err().status.as_ref());
}

#[test]
pub fn generate_info_str_test() {
    let info_str = generate_info_str();
    assert_eq!(false, info_str.is_empty());
}
