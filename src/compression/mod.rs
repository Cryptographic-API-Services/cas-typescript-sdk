use napi_derive::napi;
use cas_lib::compression::zstd;

#[napi]
pub fn ztsd_compress(data: Vec<u8>, level: i32) -> Vec<u8> {
    zstd::compress(data, level)
}

#[napi]
pub fn ztsd_decompress(data: Vec<u8>) -> Vec<u8> {
    zstd::decompress(data)
}