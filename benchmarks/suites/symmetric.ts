import {
  AESGCMSIVWrapper,
  AesKeyWrapWrapper,
  AESWrapper,
  AsconWrapper,
  ChaCha20Poly1305Wrapper,
} from "cas-typescript-sdk";
import { formatSize, ONE_KIB, ONE_MIB, randomBytes } from "../payloads";
import { Categories, defineSuite } from "../registry";

const aes = new AESWrapper();
const aesGcmSiv = new AESGCMSIVWrapper();
const chacha = new ChaCha20Poly1305Wrapper();
const ascon = new AsconWrapper();
const keyWrap = new AesKeyWrapWrapper();

/**
 * AEAD ciphers through the seal/open API, which draws a fresh nonce for every
 * message (as callers should), so each seal includes nonce generation.
 */
export const symmetricBenchmarks = defineSuite({
  name: "SymmetricBenchmarks",
  categories: [Categories.Symmetric],
  params: { name: "size", values: [ONE_KIB, ONE_MIB], format: formatSize },
  setup: (size: number) => {
    const plaintext = randomBytes(size);
    const keys = {
      aes128: aes.aes128Key(),
      aes256: aes.aes256Key(),
      aes128GcmSiv: aesGcmSiv.aes128Key(),
      aes256GcmSiv: aesGcmSiv.aes256Key(),
      chacha: chacha.generateKey(),
      ascon: ascon.ascon128Key(),
    };
    return {
      plaintext,
      keys,
      sealed: {
        aes128: aes.aes128Seal(keys.aes128, plaintext),
        aes256: aes.aes256Seal(keys.aes256, plaintext),
        aes128GcmSiv: aesGcmSiv.aes128Seal(keys.aes128GcmSiv, plaintext),
        aes256GcmSiv: aesGcmSiv.aes256Seal(keys.aes256GcmSiv, plaintext),
        chacha: chacha.seal(keys.chacha, plaintext),
        ascon: ascon.ascon128Seal(keys.ascon, plaintext),
      },
    };
  },
  benchmarks: [
    { name: "Aes128GcmSeal", fn: (c) => aes.aes128Seal(c.keys.aes128, c.plaintext) },
    { name: "Aes128GcmOpen", fn: (c) => aes.aes128Open(c.keys.aes128, c.sealed.aes128) },
    { name: "Aes256GcmSeal", fn: (c) => aes.aes256Seal(c.keys.aes256, c.plaintext) },
    { name: "Aes256GcmOpen", fn: (c) => aes.aes256Open(c.keys.aes256, c.sealed.aes256) },
    { name: "Aes128GcmSivSeal", fn: (c) => aesGcmSiv.aes128Seal(c.keys.aes128GcmSiv, c.plaintext) },
    { name: "Aes128GcmSivOpen", fn: (c) => aesGcmSiv.aes128Open(c.keys.aes128GcmSiv, c.sealed.aes128GcmSiv) },
    { name: "Aes256GcmSivSeal", fn: (c) => aesGcmSiv.aes256Seal(c.keys.aes256GcmSiv, c.plaintext) },
    { name: "Aes256GcmSivOpen", fn: (c) => aesGcmSiv.aes256Open(c.keys.aes256GcmSiv, c.sealed.aes256GcmSiv) },
    { name: "ChaCha20Poly1305Seal", fn: (c) => chacha.seal(c.keys.chacha, c.plaintext) },
    { name: "ChaCha20Poly1305Open", fn: (c) => chacha.open(c.keys.chacha, c.sealed.chacha) },
    { name: "Ascon128Seal", fn: (c) => ascon.ascon128Seal(c.keys.ascon, c.plaintext) },
    { name: "Ascon128Open", fn: (c) => ascon.ascon128Open(c.keys.ascon, c.sealed.ascon) },
  ],
});

/** AES-256 key wrapping (RFC 3394) and key wrapping with padding (RFC 5649) of a 32-byte key. */
export const aesKeyWrapBenchmarks = defineSuite({
  name: "AesKeyWrapBenchmarks",
  categories: [Categories.Symmetric],
  setup: () => {
    const kek = keyWrap.aes256GenerateKek();
    const keyToWrap = randomBytes(32, 11);
    return {
      kek,
      keyToWrap,
      wrapped: keyWrap.aes256WrapKey(kek, keyToWrap),
      wrappedWithPadding: keyWrap.aes256WrapKeyWithPadding(kek, keyToWrap),
    };
  },
  benchmarks: [
    { name: "Aes256KwWrap", fn: (c) => keyWrap.aes256WrapKey(c.kek, c.keyToWrap) },
    { name: "Aes256KwUnwrap", fn: (c) => keyWrap.aes256UnwrapKey(c.kek, c.wrapped) },
    { name: "Aes256KwpWrap", fn: (c) => keyWrap.aes256WrapKeyWithPadding(c.kek, c.keyToWrap) },
    { name: "Aes256KwpUnwrap", fn: (c) => keyWrap.aes256UnwrapKeyWithPadding(c.kek, c.wrappedWithPadding) },
  ],
});
