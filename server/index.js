import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import {
  decryptVault,
  deriveKey,
  encryptVault,
  isStrongMasterPassword,
  newSalt
} from "./crypto.js";
import { generatePassword } from "./password-generator.js";

const app = express();
const PORT = Number(process.env.PORT || 4173);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vaultPath = process.env.VAULT_PATH || path.join(
  process.env.LOCALAPPDATA || homedir(),
  "HavenPasswordManager",
  "vault.json"
);
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;

let activeKey = null;
let sessionToken = null;
let idleTimer = null;

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb", strict: true }));
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigin = process.env.NODE_ENV === "production"
    ? `http://127.0.0.1:${PORT}`
    : "http://127.0.0.1:5173";
  if (origin && origin !== allowedOrigin) {
    return res.status(403).json({ error: "Origin not allowed." });
  }
  if (req.headers.host !== `127.0.0.1:${PORT}` && req.headers.host !== `localhost:${PORT}`) {
    return res.status(403).json({ error: "Host not allowed." });
  }
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.setHeader("Vary", "Origin");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

function clearSession() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = null;
  if (activeKey) activeKey.fill(0);
  activeKey = null;
  sessionToken = null;
}

function refreshIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(clearSession, IDLE_TIMEOUT_MS);
  idleTimer.unref();
}

function requireUnlocked(req, res, next) {
  const supplied = req.get("authorization")?.replace(/^Bearer /, "");
  if (!activeKey || !sessionToken || !supplied) {
    return res.status(401).json({ error: "Vault is locked." });
  }
  const expectedBuffer = Buffer.from(sessionToken);
  const suppliedBuffer = Buffer.from(supplied);
  if (expectedBuffer.length !== suppliedBuffer.length ||
      !timingSafeEqual(expectedBuffer, suppliedBuffer)) {
    return res.status(401).json({ error: "Vault is locked." });
  }
  refreshIdleTimer();
  next();
}

async function readEnvelope() {
  const content = await readFile(vaultPath, "utf8");
  const envelope = JSON.parse(content);
  if (envelope.version !== 1 || envelope.kdf?.type !== "argon2id" ||
      !envelope.salt || !envelope.iv || !envelope.tag || !envelope.ciphertext) {
    throw new Error("Vault file has an unsupported format.");
  }
  return envelope;
}

async function writeEnvelope(envelope) {
  const directory = path.dirname(vaultPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = `${vaultPath}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify(envelope)}\n`, { mode: 0o600, flag: "wx" });
    await rename(temporaryPath, vaultPath);
  } catch (error) {
    await import("node:fs/promises").then(({ unlink }) => unlink(temporaryPath).catch(() => {}));
    throw error;
  }
}

function normalizeRecords(value) {
  if (!Array.isArray(value) || value.length > 10000) {
    throw new Error("Vault entries must be an array of at most 10,000 records.");
  }
  return value.map((record) => {
    if (!record || typeof record !== "object" || typeof record.id !== "string" ||
        record.id.length > 100 || typeof record.website !== "string" ||
        typeof record.username !== "string" || typeof record.password !== "string" ||
        typeof record.totpSecret !== "string" || typeof record.notes !== "string") {
      throw new Error("Vault entry has invalid fields.");
    }
    const result = {
      id: record.id,
      website: record.website.slice(0, 256),
      username: record.username.slice(0, 256),
      password: record.password.slice(0, 4096),
      totpSecret: record.totpSecret.slice(0, 256),
      notes: record.notes.slice(0, 4096)
    };
    if (Object.values(result).some((field) => field.length > 4096)) {
      throw new Error("Vault entry field is too long.");
    }
    return result;
  });
}

app.get("/api/status", async (_req, res) => {
  try {
    await readFile(vaultPath);
    res.json({ configured: true, unlocked: Boolean(activeKey) });
  } catch (error) {
    if (error.code === "ENOENT") return res.json({ configured: false, unlocked: false });
    res.status(500).json({ error: "Unable to read vault status." });
  }
});

app.post("/api/setup", async (req, res) => {
  if (activeKey) return res.status(409).json({ error: "Vault is already unlocked." });
  let exists = false;
  try {
    await readFile(vaultPath);
    exists = true;
  } catch (error) {
    if (error.code !== "ENOENT") return res.status(500).json({ error: "Unable to check vault file." });
  }
  if (exists) return res.status(409).json({ error: "Vault already exists." });
  const { masterPassword } = req.body || {};
  if (!isStrongMasterPassword(masterPassword)) {
    return res.status(400).json({
      error: "Use at least 14 characters and at least three character types."
    });
  }
  const salt = newSalt();
  let key;
  try {
    key = await deriveKey(masterPassword, salt);
    await writeEnvelope(encryptVault({ records: [] }, key, salt));
    activeKey = key;
    sessionToken = randomBytes(32).toString("base64url");
    refreshIdleTimer();
    res.json({ token: sessionToken, records: [] });
  } catch (error) {
    key?.fill(0);
    res.status(500).json({ error: "Unable to create the encrypted vault." });
  }
});

app.post("/api/unlock", async (req, res) => {
  if (activeKey) return res.status(409).json({ error: "Vault is already unlocked." });
  const { masterPassword } = req.body || {};
  if (typeof masterPassword !== "string" || masterPassword.length > 1024) {
    return res.status(400).json({ error: "Enter your master password." });
  }
  let envelope;
  try {
    envelope = await readEnvelope();
  } catch (error) {
    if (error.code === "ENOENT") return res.status(404).json({ error: "Vault has not been set up." });
    return res.status(500).json({ error: "Unable to read vault file." });
  }
  let key;
  try {
    key = await deriveKey(masterPassword, Buffer.from(envelope.salt, "base64"));
    const vault = decryptVault(envelope, key);
    if (!Array.isArray(vault.records)) throw new Error("Invalid vault contents.");
    activeKey = key;
    sessionToken = randomBytes(32).toString("base64url");
    refreshIdleTimer();
    res.json({ token: sessionToken, records: vault.records });
  } catch {
    key?.fill(0);
    res.status(401).json({ error: "Incorrect master password or damaged vault." });
  }
});

app.post("/api/lock", requireUnlocked, (_req, res) => {
  clearSession();
  res.json({ locked: true });
});

app.get("/api/vault", requireUnlocked, async (_req, res) => {
  try {
    const vault = decryptVault(await readEnvelope(), activeKey);
    res.json({ records: normalizeRecords(vault.records) });
  } catch {
    res.status(500).json({ error: "Unable to decrypt vault contents." });
  }
});

app.put("/api/vault", requireUnlocked, async (req, res) => {
  let records;
  try {
    records = normalizeRecords(req.body?.records);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Invalid vault entries." });
  }
  try {
    const envelope = await readEnvelope();
    await writeEnvelope(encryptVault({ records }, activeKey, Buffer.from(envelope.salt, "base64")));
    res.json({ saved: true });
  } catch {
    res.status(500).json({ error: "Unable to save encrypted vault." });
  }
});

app.post("/api/generate-password", requireUnlocked, (req, res) => {
  try {
    res.json({ password: generatePassword(req.body || {}) });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.resolve(__dirname, "..", "dist"), {
    index: false,
    setHeaders(res) {
      res.setHeader("Cache-Control", "no-store");
    }
  }));
  app.get("*", (_req, res) => res.sendFile(path.resolve(__dirname, "..", "dist", "index.html")));
}

const server = app.listen(PORT, "127.0.0.1", () => {
  console.log(`Haven is listening at http://127.0.0.1:${PORT}`);
});

process.on("SIGINT", () => {
  clearSession();
  server.close(() => process.exit(0));
});
process.on("SIGTERM", () => {
  clearSession();
  server.close(() => process.exit(0));
});
