import { HasherType } from "./hasher-type";
import { SHAWrapper } from "./sha-wrapper";

export class HasherFactory {
    getHasher(type: HasherType): any {
        let result: SHAWrapper = new SHAWrapper();
        switch(type) {

        }
        return result;
    }
}