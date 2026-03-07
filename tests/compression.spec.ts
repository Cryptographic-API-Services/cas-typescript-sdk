import { test, expect } from "@playwright/test";
import { ZTSDWrapper } from "../src-ts/compression";

test("Compress and Decompress with ZTSD", () => {
    const ztsdWrapper = new ZTSDWrapper();
    const originalData: string = "This is some data to compress and decompress using ZTSD. Lets continue to increase the size of it, testing 1234";
    const encoder = new TextEncoder();
    const originalBytes: Array<number> = Array.from(encoder.encode(originalData));
    const compressionLevel: number = 10; // Choose a compression level between -22 and 22

    // Compress the data
    const compressedData: Array<number> = ztsdWrapper.compress(originalBytes, compressionLevel);
    expect(compressedData).toBeDefined();
    expect(compressedData.length).toBeLessThan(originalBytes.length);

    // Decompress the data
    const decompressedData: Array<number> = ztsdWrapper.decompress(compressedData);
    expect(decompressedData).toBeDefined();
    expect(decompressedData.length).toEqual(originalBytes.length);
    const decoder = new TextDecoder();
    const decompressedString: string = decoder.decode(new Uint8Array(decompressedData));
    expect(decompressedString).toEqual(originalData);
});

test("Compress with invalid level should throw error", () => {
    const ztsdWrapper = new ZTSDWrapper();
    const data: string = "This is some data to compress and decompress using ZTSD. Lets continue to increase the size of it, testing 1234";
    const encoder = new TextEncoder();
    const bytes: Array<number> = Array.from(encoder.encode(data));
    const invalidLevel: number = 30; // Invalid compression level
    expect(() => ztsdWrapper.compress(bytes, invalidLevel)).toThrowError("Compression level must be between -22 and 22.");
});

test("Decompress with empty data should throw error", () => {
    const ztsdWrapper = new ZTSDWrapper();
    expect(() => ztsdWrapper.decompress([])).toThrowError("Data to decompress cannot be null or empty.");
});