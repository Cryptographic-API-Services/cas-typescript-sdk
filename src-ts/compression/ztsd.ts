import { ztsdCompress, ztsdDecompress } from "../../index";

export class ZTSDWrapper {
    constructor() {

    }

    /**
     * Datas to the byte array to compress and the level of encryption.
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
     * Decompresses and previosuly compressed byte array with ZSTD.
     * No level is required to decompress.
     * @param data 
     * @returns 
     */
    public decompress(data: Array<number>): Array<number> {
        if (data == null || data?.length === 0) {
            throw new Error("Data to decompress cannot be null or empty.");
        }
        return ztsdDecompress(data);
    }
}