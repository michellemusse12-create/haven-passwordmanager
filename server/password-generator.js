import { randomInt } from "node:crypto";

const CHARACTER_SETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?/|~"
};

export function generatePassword(options = {}) {
  const length = options.length ?? 20;
  const selected = Object.keys(CHARACTER_SETS).filter(
    (name) => options[name] !== false
  );
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new RangeError("Password length must be between 8 and 128.");
  }
  if (selected.length === 0 || length < selected.length) {
    throw new RangeError("Choose at least one character set and enough characters.");
  }

  const pool = selected.map((name) => CHARACTER_SETS[name]).join("");
  const characters = selected.map((name) => {
    const set = CHARACTER_SETS[name];
    return set[randomInt(set.length)];
  });
  while (characters.length < length) {
    characters.push(pool[randomInt(pool.length)]);
  }
  for (let i = characters.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    [characters[i], characters[j]] = [characters[j], characters[i]];
  }
  return characters.join("");
}
