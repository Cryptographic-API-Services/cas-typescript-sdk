export class ED25519DalekSignRequest {
    keyPair: string;
    dataToSign: string;

    constructor(keyPair: string, dataToSign: string) {
        this.keyPair = keyPair;
        this.dataToSign = dataToSign;
    }
}