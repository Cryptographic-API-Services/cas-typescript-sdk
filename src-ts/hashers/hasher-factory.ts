import { Blake2Wrapper } from "./blake2-wrapper";
import { HasherType } from "./hasher-type";
import { SHAWrapper } from "./sha-wrapper";

export class HasherFactory {
    /**
     * Get the appropriate hasher wrapper based upon the type based in.
     * @param type 
     * @returns 
     */
    getHasher(type: HasherType): any {
        let result: SHAWrapper = new SHAWrapper();
        switch(type) {
            case HasherType.Blake2:
                result = new Blake2Wrapper(); 
        }
        return result;
    }
}