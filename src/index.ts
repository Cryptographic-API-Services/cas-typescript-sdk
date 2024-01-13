import { Argon2Wrapper } from "./password-hashers/argon2-wrapper";

let wrapper = new Argon2Wrapper();
let hash = wrapper.hashPassword('testing');
console.log(hash);

export {
    Argon2Wrapper
}