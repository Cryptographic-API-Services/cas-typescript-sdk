export interface IHasherBase {
    hash_512(dataToHash: number[]): number[];
    verify_512(dataToHash: number[], dataToVerify: number[]): boolean;
    hash_256(dataToHash: number[]): number[];
    verify_256(dataToHash: number[], dataToVerify: number[]): boolean;
}