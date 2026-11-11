import argon2 from "argon2";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export const KDF = Object.freeze({
  type: "argon2id",
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16
});

export function isStrongMasterPassword(password) {
  if (typeof password !== "string" || password.length < 14 || password.length > 1024) return false;
  const classes = [
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password)
  ].filter(Boolean).length;
  return classes >= 3;
}

export async function deriveKey(password, salt) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    salt,
    memoryCost: KDF.memoryCost,
    timeCost: KDF.timeCost,
    parallelism: KDF.parallelism,
    hashLength: KDF.hashLength,
    raw: true
  });
}

export function encryptVault(value, key, salt) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final()
  ]);
  return {
    version: 1,
    kdf: KDF,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64")
  };
}

export function decryptVault(envelope, key) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(envelope.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final()
  ]).toString("utf8");
  return JSON.parse(plaintext);
}

export function newSalt() {
  return randomBytes(KDF.saltLength);
}
