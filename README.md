# Haven Password Manager

Haven is a local-first password manager built with React and Node.js. The backend listens only on `127.0.0.1`; vault data is stored as an authenticated AES-256-GCM encrypted file, with its key derived from the master password using Argon2id. Decrypted data is held only in process/browser memory while unlocked.

## Run locally

Requirements: Node.js 20+ and npm.

```sh
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. The development server starts the React UI and local API. For a production build, run `npm run build` then `npm start` and open `http://127.0.0.1:4173`.

The encrypted vault is saved under `%LOCALAPPDATA%\HavenPasswordManager\vault.json` on Windows (or `~\HavenPasswordManager\vault.json` when `LOCALAPPDATA` is unavailable). Set `VAULT_PATH` to choose another location. Back up this encrypted file securely; losing it or forgetting the master password means the vault cannot be recovered.

## Security behavior

- The master password must be at least 14 characters and use at least three character classes during setup.
- Argon2id uses a 16-byte random salt, 64 MiB memory, three iterations, and one lane. AES-256-GCM uses a fresh 96-bit nonce for every vault save.
- The master password is not persisted. A random bearer token and derived key exist only in process memory; the token is not put in browser storage. The vault locks after five minutes without authenticated API activity and when the UI's Lock control is used.
- Login fields, notes, and TOTP setup keys are encrypted together. Password generation uses Node's cryptographic random-number generator. TOTP codes use RFC 6238 with SHA-1 and six digits.
- Copy uses the browser clipboard API and attempts to clear the copied value after 30 seconds, but browser permission restrictions may prevent clearing. The clipboard should not be considered secure storage.

This project is a practical starter, not a professionally audited password manager. It does not protect against a compromised operating system/browser, malicious browser extensions, memory inspection, or physical access to an unlocked device. Use only on a trusted device; do not expose the loopback API through a proxy or port-forward.

## Tests

```sh
npm test
```

## Login automation example

`automation/fill-login.example.js` is an opt-in Playwright template for a site and account you are authorized to access. It reads credentials from environment variables, avoids logging them, and intentionally does not submit the form. Install Playwright separately if you choose to use it.
