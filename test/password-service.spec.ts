// tests/calculator.spec.tx
import { assert } from "chai";
import { EASConfiguration, PasswordService, TokenCache } from "../src";
import { BCryptHashPasswordResponse } from "../src/types/password/bcrypt-hash-password-response";
import { BCryptVerifyResponse } from "../src/types/password/bcrypt-verify-response";
import { SCryptHashPasswordResponse } from "../src/types/password/scrypt-hash-password-response";
import { ScryptVerifyResponse } from "../src/types/password/scrypt-verify-response";
import { Argon2HashPasswordResponse } from "../src/types/password/argon2-hash-password-response";
import { Argon2VerifyResponse } from "../src/types/password/argon2-verify-response";
import { BcryptEncryptBatchResponse } from "../src/types/password/bcrypt-hash-password-batch-response";
import { ScryptHashPasswordBatchResponse } from "../src/types/password/scrypt-hash-password-batch-response";
import { Argon2HashPasswordBatchResponse } from "../src/types/password/argon2-hash-password-batch-response";

describe("Password Service Tests", () => {
   EASConfiguration.apiKey = process.env.EasApiKey || '';
   const tokenCache: TokenCache = new TokenCache();
   const passwordService = new PasswordService();
   
   it("should hash a password with bcrypt", async () => {
      const token = await tokenCache.getToken();
      const password: string = "password";
      const hashedPassword: BCryptHashPasswordResponse = await passwordService.bcryptHashPassword(token, password);
      assert.isString(hashedPassword.hashedPassword);
      assert.isNotNull(hashedPassword.hashedPassword);
   });

   it("should hash a batch of passwords with bcrypt", async () => {
      const token: string = await tokenCache.getToken();
      const passwords: string[] = ["password", "password1", "password2", "password3", "password4", "password5"];
      const hashedPasswords: BcryptEncryptBatchResponse = await passwordService.bcryptHashBatch(token, passwords);
      assert.exists(hashedPasswords.hashedPasswords);
      assert.isTrue(hashedPasswords.hashedPasswords.length > 0);
      for (var i = 0; i < hashedPasswords.hashedPasswords.length; i++) {
         assert.isString(hashedPasswords.hashedPasswords[i]);
      }
   });   

   it("should verify a password with bcrypt", async () => {
      const token = await tokenCache.getToken();
      const password: string = "password";
      const hashedPassword: BCryptHashPasswordResponse = await passwordService.bcryptHashPassword(token, password);
      const verifyPassword: BCryptVerifyResponse = await passwordService.bcryptVerify(token, hashedPassword.hashedPassword, password);
      assert.isTrue(verifyPassword.isValid);
   });

   it("should hash a password with scrypt", async () => {
      const token = await tokenCache.getToken();
      const password: string = "password";
      const hashedPassword: SCryptHashPasswordResponse = await passwordService.scryptHashPassword(token, password);
      assert.isString(hashedPassword.hashedPassword);
      assert.isNotNull(hashedPassword.hashedPassword);
   });

   it("should hash a batch of passwords with scrypt", async () => {
      const token: string = await tokenCache.getToken();
      const passwords: string[] = ["password", "password1", "password2", "password3", "password4", "password5"];
      const hashedPasswords: ScryptHashPasswordBatchResponse = await passwordService.scryptHashBatch(token, passwords);
      assert.exists(hashedPasswords.hashedPasswords);
      assert.isTrue(hashedPasswords.hashedPasswords.length > 0);
      for (var i = 0; i < hashedPasswords.hashedPasswords.length; i++) {
         assert.isString(hashedPasswords.hashedPasswords[i]);
      }
   });

   it("should verify a password with scrypt", async () => {
      const token = await tokenCache.getToken();
      const password: string = "password";
      const hashedPassword: SCryptHashPasswordResponse = await passwordService.scryptHashPassword(token, password);
      const verifiedResponse: ScryptVerifyResponse = await passwordService.scryptVerify(token, hashedPassword.hashedPassword, password);
      assert.isTrue(verifiedResponse.isValid);
   });

   it("should hash a password with Argon2", async () => {
      const token = await tokenCache.getToken();
      const password: string = "password";
      const hashedPassword: Argon2HashPasswordResponse = await passwordService.argon2HashPassword(token, password);
      assert.isString(hashedPassword.hashedPassword);
      assert.isNotNull(hashedPassword.hashedPassword);
   });

   it("shoud hash a batch of passwords with Argon2", async () => {
      const token: string = await tokenCache.getToken();
      const passwords: string[] = ["password", "password1", "password2", "password3", "password4", "password5"];
      const hashedPasswords: Argon2HashPasswordBatchResponse = await passwordService.argon2HashBatch(token, passwords);
      assert.exists(hashedPasswords.hashedPasswords);
      assert.isTrue(hashedPasswords.hashedPasswords.length > 0);
      for (var i = 0; i < hashedPasswords.hashedPasswords.length; i++) {
         assert.isString(hashedPasswords.hashedPasswords[i]);
      }
   });

   it("should verify a password with Argon2", async () => {
      const token = await tokenCache.getToken();
      const password: string = "password";
      const hashedPassword: Argon2HashPasswordResponse = await passwordService.argon2HashPassword(token, password);
      const verified: Argon2VerifyResponse = await passwordService.argon2Verify(token, hashedPassword.hashedPassword, password);
      assert.isTrue(verified.isValid);
   });
});