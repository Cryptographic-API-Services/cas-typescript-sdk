use napi_derive::napi;
use cas_lib::compression::zstd;

#[napi]
pub fn ztsd_compress(data: Vec<u8>, level: i32) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(zstd::compress(data, level))
}

#[napi]
pub fn ztsd_decompress(data: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(zstd::decompress(data))
}

// napi has no `usize`, so the limit arrives as an `i64` and must be positive and
// fit in `usize` (at most 4 GiB - 1 on 32-bit targets).
#[napi]
pub fn ztsd_decompress_with_limit(data: Vec<u8>, max_output_size: i64) -> napi::Result<Vec<u8>> {
    let max_output_size = usize::try_from(max_output_size)
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| napi::Error::from_reason("Max output size must be a positive integer."))?;
    crate::map_cas_err(zstd::decompress_with_limit(data, max_output_size))
}

#[cfg(test)]
const MIB: usize = 1024 * 1024;

#[test]
fn ztsd_compress_decompress_test() {
    let data = b"This is some data to compress and decompress using ZTSD.".to_vec();
    let compressed = ztsd_compress(data.clone(), 10).unwrap();
    assert_eq!(data, ztsd_decompress(compressed.clone()).unwrap());
    assert_eq!(data, ztsd_decompress_with_limit(compressed, data.len() as i64).unwrap());
}

#[test]
fn ztsd_decompress_default_limit_test() {
    let data = vec![0u8; 65 * MIB];
    let compressed = ztsd_compress(data.clone(), 3).unwrap();
    assert!(compressed.len() < MIB);
    let err = ztsd_decompress(compressed.clone()).unwrap_err();
    assert_eq!("decompressed output exceeds the size limit", err.reason);
    assert_eq!(data, ztsd_decompress_with_limit(compressed, (70 * MIB) as i64).unwrap());
}

#[test]
fn ztsd_decompress_with_limit_below_output_test() {
    let data = vec![0u8; 1024];
    let compressed = ztsd_compress(data, 3).unwrap();
    let err = ztsd_decompress_with_limit(compressed.clone(), 1023).unwrap_err();
    assert_eq!("decompressed output exceeds the size limit", err.reason);
    assert!(ztsd_decompress_with_limit(compressed, 1024).is_ok());
}

#[test]
fn ztsd_decompress_with_limit_rejects_non_positive_limit_test() {
    let compressed = ztsd_compress(vec![0u8; 16], 3).unwrap();
    assert!(ztsd_decompress_with_limit(compressed.clone(), 0).is_err());
    assert!(ztsd_decompress_with_limit(compressed, -1).is_err());
}
