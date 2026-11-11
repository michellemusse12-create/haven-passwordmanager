const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function decodeBase32(secret) {
  const value = secret.toUpperCase().replace(/[\s=-]/g, "");
  if (!value || /[^A-Z2-7]/.test(value)) throw new Error("Invalid Base32 secret");
  let bits = "";
  for (const character of value) bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  if (bytes.length < 10) throw new Error("TOTP secret is too short");
  return new Uint8Array(bytes);
}

export async function getTotp(secret, now = Date.now()) {
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const counter = BigInt(Math.floor(now / 30000));
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, counter);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}
