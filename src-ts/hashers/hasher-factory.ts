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

        }
        return result;
    }
}