import { createHmac } from "node:crypto";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function decodeBase32(secret) {
  const normalized = secret.toUpperCase().replace(/[\s=-]/g, "");
  if (!normalized || /[^A-Z2-7]/.test(normalized)) {
    throw new Error("TOTP secret must be a valid Base32 value.");
  }
  let bits = "";
  for (const character of normalized) {
    bits += BASE32.indexOf(character).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  if (bytes.length < 10) throw new Error("TOTP secret is too short.");
  return Buffer.from(bytes);
}

export function generateTotp(secret, timestamp = Date.now(), digits = 6) {
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new RangeError("TOTP digits must be between 6 and 8.");
  }
  const counter = BigInt(Math.floor(timestamp / 1000 / 30));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % (10 ** digits)).padStart(digits, "0");
}
