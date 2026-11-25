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

const MIB = 1024 * 1024;
const LIMIT_ERROR = "decompressed output exceeds the size limit";

test("Decompress over the 64 MiB default limit throws unless maxOutputSize allows it", () => {
    // Marshalling tens of millions of numbers across napi takes several seconds each way.
    test.slow();
    const ztsdWrapper = new ZTSDWrapper();
    const size = 65 * MIB;
    // push builds a packed array far faster than new Array(size).fill(0).
    const zeros: Array<number> = [];
    for (let i = 0; i < size; i++) {
        zeros.push(0);
    }
    const compressedData = ztsdWrapper.compress(zeros, 3);
    zeros.length = 0;
    expect(compressedData.length).toBeLessThan(MIB);

    expect(() => ztsdWrapper.decompress(compressedData)).toThrowError(LIMIT_ERROR);

    const decompressedData = ztsdWrapper.decompress(compressedData, 70 * MIB);
    expect(decompressedData.length).toEqual(size);
    expect(decompressedData.every((byte) => byte === 0)).toBe(true);
});

test("Decompress with maxOutputSize below the real output throws", () => {
    const ztsdWrapper = new ZTSDWrapper();
    const originalBytes = Array.from(new TextEncoder().encode("This is some data to compress and decompress using ZTSD."));
    const compressedData = ztsdWrapper.compress(originalBytes, 3);
    expect(() => ztsdWrapper.decompress(compressedData, originalBytes.length - 1)).toThrowError(LIMIT_ERROR);
    expect(ztsdWrapper.decompress(compressedData, originalBytes.length)).toEqual(originalBytes);
});

test("Decompress with an invalid maxOutputSize throws", () => {
    const ztsdWrapper = new ZTSDWrapper();
    const compressedData = ztsdWrapper.compress([1, 2, 3, 4], 3);
    for (const maxOutputSize of [0, -1, 1.5, NaN, Infinity]) {
        expect(() => ztsdWrapper.decompress(compressedData, maxOutputSize)).toThrowError("Max output size must be a positive integer.");
    }
});