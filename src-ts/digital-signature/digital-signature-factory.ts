import { DigitalSignatureSHA512Wrapper } from "./digital-siganture-sha-512";

export enum DigitalSignatureType {
    SHA512 = 1,
    SHA256 = 2
}

export class DigitalSignatureFactory {
    public static get(type: DigitalSignatureType) {
        let ds = new DigitalSignatureSHA512Wrapper();
        switch(type) {

        }
        return ds;
    }
}