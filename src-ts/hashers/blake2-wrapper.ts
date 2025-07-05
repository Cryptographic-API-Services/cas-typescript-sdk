import { blake2Sha512Verify, blake2Sha256Verify, blake2Sha256, blake2Sha512 } from "../../index";
import { IHasherBase } from "./hasher-base";

export class Blake2Wrapper implements IHasherBase {
    hash512(dataToHash: number[]): number[] {
        return blake2Sha512(dataToHash);
    }

    verify512(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha512Verify(dataToHash, dataToVerify);
    }

    hash256(dataToHash: number[]): number[] {
        return blake2Sha256(dataToHash);
    }
    
    verify256(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha256Verify(dataToHash, dataToVerify);
    }
}