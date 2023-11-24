export class SHA512ED25519DalekSignRequest {
    dataToSign: string;

    constructor(dataToSign: string) {
        this.dataToSign = dataToSign;
    }
}