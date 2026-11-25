import {
  aes128KwGenerateKek,
  aes128KwUnwrapKey,
  aes128KwUnwrapKeyWithPadding,
  aes128KwWrapKey,
  aes128KwWrapKeyWithPadding,
  aes256KwGenerateKek,
  aes256KwUnwrapKey,
  aes256KwUnwrapKeyWithPadding,
  aes256KwWrapKey,
  aes256KwWrapKeyWithPadding,
} from "../../index";

/**
 * AES key wrapping: protects key material under a key-encryption key (KEK).
 *
 * - KW (RFC 3394 / NIST SP 800-38F) wraps keys that are a multiple of 8 bytes and at least
 *   16 bytes long. The wrapped key is 8 bytes longer than the input.
 * - KWP (RFC 5649 / NIST SP 800-38F) wraps keys of any non-zero length, padding them to a
 *   multiple of 8 bytes first.
 *
 * Unwrapping verifies an integrity check value, so a wrong KEK or a modified wrapped key
 * throws a `CasError` with code `CAS_DECRYPTION_FAILED`. Wrong lengths throw `CAS_INVALID_KEY`
 * (KEK) or `CAS_INVALID_INPUT` (key to wrap / wrapped key). Key wrapping is deterministic and
 * meant for wrapping keys, not for encrypting general data: use an AEAD for that.
 */
export class AesKeyWrapWrapper {

    /**
     * Generates a random 16 byte AES-128 key-encryption key (KEK).
     * @returns Array<number>
     */

    public aes128GenerateKek(): Array<number> {
        return aes128KwGenerateKek();
    }

    /**
     * Generates a random 32 byte AES-256 key-encryption key (KEK).
     * @returns Array<number>
     */

    public aes256GenerateKek(): Array<number> {
        return aes256KwGenerateKek();
    }

    /**
     * Wraps a key with AES-128-KW (RFC 3394).
     * @param kek 16 byte key-encryption key.
     * @param keyToWrap Key material: a multiple of 8 bytes, at least 16 bytes.
     * @returns The wrapped key, 8 bytes longer than `keyToWrap`.
     */

    public aes128WrapKey(kek: Array<number>, keyToWrap: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(keyToWrap, "keyToWrap");
        return aes128KwWrapKey(kek, keyToWrap);
    }

    /**
     * Unwraps an AES-128-KW (RFC 3394) wrapped key and verifies its integrity.
     * @param kek 16 byte key-encryption key.
     * @param wrappedKey Output of `aes128WrapKey`.
     * @returns The original key material.
     */

    public aes128UnwrapKey(kek: Array<number>, wrappedKey: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(wrappedKey, "wrappedKey");
        return aes128KwUnwrapKey(kek, wrappedKey);
    }

    /**
     * Wraps a key of any non-zero length with AES-128-KWP (RFC 5649).
     * @param kek 16 byte key-encryption key.
     * @param keyToWrap Key material, at least 1 byte.
     * @returns The wrapped key, a multiple of 8 bytes.
     */

    public aes128WrapKeyWithPadding(kek: Array<number>, keyToWrap: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(keyToWrap, "keyToWrap");
        return aes128KwWrapKeyWithPadding(kek, keyToWrap);
    }

    /**
     * Unwraps an AES-128-KWP (RFC 5649) wrapped key and verifies its integrity and padding.
     * @param kek 16 byte key-encryption key.
     * @param wrappedKey Output of `aes128WrapKeyWithPadding`.
     * @returns The original key material.
     */

    public aes128UnwrapKeyWithPadding(kek: Array<number>, wrappedKey: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(wrappedKey, "wrappedKey");
        return aes128KwUnwrapKeyWithPadding(kek, wrappedKey);
    }

    /**
     * Wraps a key with AES-256-KW (RFC 3394).
     * @param kek 32 byte key-encryption key.
     * @param keyToWrap Key material: a multiple of 8 bytes, at least 16 bytes.
     * @returns The wrapped key, 8 bytes longer than `keyToWrap`.
     */

    public aes256WrapKey(kek: Array<number>, keyToWrap: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(keyToWrap, "keyToWrap");
        return aes256KwWrapKey(kek, keyToWrap);
    }

    /**
     * Unwraps an AES-256-KW (RFC 3394) wrapped key and verifies its integrity.
     * @param kek 32 byte key-encryption key.
     * @param wrappedKey Output of `aes256WrapKey`.
     * @returns The original key material.
     */

    public aes256UnwrapKey(kek: Array<number>, wrappedKey: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(wrappedKey, "wrappedKey");
        return aes256KwUnwrapKey(kek, wrappedKey);
    }

    /**
     * Wraps a key of any non-zero length with AES-256-KWP (RFC 5649).
     * @param kek 32 byte key-encryption key.
     * @param keyToWrap Key material, at least 1 byte.
     * @returns The wrapped key, a multiple of 8 bytes.
     */

    public aes256WrapKeyWithPadding(kek: Array<number>, keyToWrap: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(keyToWrap, "keyToWrap");
        return aes256KwWrapKeyWithPadding(kek, keyToWrap);
    }

    /**
     * Unwraps an AES-256-KWP (RFC 5649) wrapped key and verifies its integrity and padding.
     * @param kek 32 byte key-encryption key.
     * @param wrappedKey Output of `aes256WrapKeyWithPadding`.
     * @returns The original key material.
     */

    public aes256UnwrapKeyWithPadding(kek: Array<number>, wrappedKey: Array<number>): Array<number> {
        this.requireBytes(kek, "kek");
        this.requireBytes(wrappedKey, "wrappedKey");
        return aes256KwUnwrapKeyWithPadding(kek, wrappedKey);
    }

    private requireBytes(value: Array<number>, name: string): void {
        if (!Array.isArray(value)) {
            throw new Error(`AES key wrap ${name} must be a byte array`);
        }
    }
}
