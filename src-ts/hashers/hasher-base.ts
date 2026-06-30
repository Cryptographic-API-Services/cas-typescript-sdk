export interface IHasherBase {
    hash512(dataToHash: Uint8Array): Uint8Array;
    verify512(dataToHash: Uint8Array, dataToVerify: Uint8Array): boolean;
    hash256(dataToHash: Uint8Array): Uint8Array;
    verify256(dataToHash: Uint8Array, dataToVerify: Uint8Array): boolean;
}