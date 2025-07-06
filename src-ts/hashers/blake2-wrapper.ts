import { blake2Sha512Verify, blake2Sha256Verify, blake2Sha256, blake2Sha512, blake2Sha512Threadpool, blake2Sha512VerifyThreadpool, blake2Sha256Threadpool, blake2Sha256VerifyThreadpool } from "../../index";
import { IHasherBase } from "./hasher-base";

export class Blake2Wrapper implements IHasherBase {
    hash512(dataToHash: number[]): number[] {
        return blake2Sha512(dataToHash);
    }

    hash512Threadpool(dataToHash: number[]): number[] {
        return blake2Sha512Threadpool(dataToHash);
    }

    verify512(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha512Verify(dataToHash, dataToVerify);
    }

    verify512Threadpool(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha512VerifyThreadpool(dataToHash, dataToVerify);
    }

    hash256(dataToHash: number[]): number[] {
        return blake2Sha256(dataToHash);
    }

    hash256Threadpool(dataToHash: number[]): number[] {
        return blake2Sha256Threadpool(dataToHash);
    }
    
    verify256(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha256Verify(dataToHash, dataToVerify);
    }

    verify256Threadpool(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha256VerifyThreadpool(dataToHash, dataToVerify);
    }
}