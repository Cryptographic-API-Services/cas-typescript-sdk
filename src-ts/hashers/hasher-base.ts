export interface IHasherBase {
    hash512(dataToHash: number[]): number[];
    verify512(dataToHash: number[], dataToVerify: number[]): boolean;
    hash256(dataToHash: number[]): number[];
    verify256(dataToHash: number[], dataToVerify: number[]): boolean;
}