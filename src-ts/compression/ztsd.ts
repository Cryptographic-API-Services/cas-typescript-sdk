import { ztsdCompress, ztsdDecompress, ztsdDecompressWithLimit } from "../../index";

export class ZTSDWrapper {
    constructor() {

    }

    /**
     * Compresses a byte array with ZSTD at the given compression level.
     * Zstandard (zstd) supports 22 compression levels, ranging from -22 to 22. Lower levels, such as 1–9, 
     * are faster but result in larger file sizes, while higher levels, such as 10–22, provide better compression ratios.
     * @param data 
     * @param level 
     * @returns 
     */
    public compress(data: Array<number>, level: number): Array<number> {
        if (data == null || data?.length === 0) {
            throw new Error("Data to compress cannot be null or empty.");
        }
        if (level < -22 || level > 22) {
            throw new Error("Compression level must be between -22 and 22.");
        }
        return ztsdCompress(data, level);
    }

    /**
     * Decompresses a previously compressed byte array with ZSTD.
     * No level is required to decompress.
     *
     * Output is capped at `maxOutputSize` bytes, 64 MiB by default, so a small crafted input
     * (a decompression bomb) cannot exhaust memory. Data that would decompress to more than the
     * limit throws `"decompressed output exceeds the size limit"`. Only raise the limit for
     * trusted input, and keep it no larger than the biggest output you expect.
     *
     * Frames that declare a back-reference window over 128 MiB, and legacy (pre-v0.8) zstd
     * frames, are rejected.
     * @param data 
     * @param maxOutputSize maximum decompressed size in bytes, a positive integer. Defaults to 64 MiB.
     * @returns 
     */
    public decompress(data: Array<number>, maxOutputSize?: number): Array<number> {
        if (data == null || data?.length === 0) {
            throw new Error("Data to decompress cannot be null or empty.");
        }
        if (maxOutputSize === undefined) {
            return ztsdDecompress(data);
        }
        if (!Number.isSafeInteger(maxOutputSize) || maxOutputSize <= 0) {
            throw new Error("Max output size must be a positive integer.");
        }
        return ztsdDecompressWithLimit(data, maxOutputSize);
    }
}
