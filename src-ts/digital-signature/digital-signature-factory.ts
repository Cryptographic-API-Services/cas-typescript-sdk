import { DigitalSignatureSHA512Wrapper } from "./digital-siganture-sha-512";
import { DigitalSignatureSHA256Wrapper } from "./digital-signaturte-sha-256";

export enum DigitalSignatureType {
    SHA512 = 1,
    SHA256 = 2
}

export class DigitalSignatureFactory {

    /**
     * Get the appropriate digital signature wrapper based upon the type passed in.
     * @param type 
     * @returns 
     */
    public static get(type: DigitalSignatureType) {
        let ds = new DigitalSignatureSHA512Wrapper();
        switch (type) {
            case DigitalSignatureType.SHA256:
                ds = new DigitalSignatureSHA256Wrapper();
                break;
        }
        return ds;
    }
}