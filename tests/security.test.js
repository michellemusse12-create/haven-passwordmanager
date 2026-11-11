import test from "node:test";
import assert from "node:assert/strict";
import {
  decryptVault,
  deriveKey,
  encryptVault,
  isStrongMasterPassword,
  newSalt
} from "../server/crypto.js";
import { generatePassword } from "../server/password-generator.js";
import { generateTotp } from "../server/totp.js";

test("master password policy requires length and character variety", () => {
  assert.equal(isStrongMasterPassword("short"), false);
  assert.equal(isStrongMasterPassword("correct horse battery staple"), false);
  assert.equal(isStrongMasterPassword("M0re-Than-14_chars"), true);
});

test("password generator includes each selected character class", () => {
  const password = generatePassword({ length: 20 });
  assert.equal(password.length, 20);
  assert.match(password, /[A-Z]/);
  assert.match(password, /[a-z]/);
  assert.match(password, /\d/);
  assert.match(password, /[^A-Za-z0-9]/);
  assert.throws(() => generatePassword({ length: 7 }), RangeError);
});

test("TOTP follows RFC 6238 SHA-1 test vector", () => {
  assert.equal(generateTotp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59000), "287082");
});

test("vault encryption authenticates ciphertext and decrypts with derived key", async () => {
  const salt = newSalt();
  const key = await deriveKey("M0re-Than-14_chars", salt);
  const envelope = encryptVault({ records: [{ password: "secret" }] }, key, salt);
  assert.deepEqual(decryptVault(envelope, key), { records: [{ password: "secret" }] });
  envelope.ciphertext = Buffer.from("tampered").toString("base64");
  assert.throws(() => decryptVault(envelope, key));
  key.fill(0);
});
