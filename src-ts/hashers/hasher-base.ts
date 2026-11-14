/**
 * Data accepted by the hashers. `null` / `undefined` are treated as the empty
 * message, which has a well-defined digest (e.g. SHA2-256("") = e3b0c442...).
 */
export type HashInput = number[] | null | undefined;

export interface IHasherBase {
    hash512(dataToHash: HashInput): number[];
    verify512(hashToVerify: HashInput, dataToVerify: HashInput): boolean;
    hash256(dataToHash: HashInput): number[];
    verify256(hashToVerify: HashInput, dataToVerify: HashInput): boolean;
}
