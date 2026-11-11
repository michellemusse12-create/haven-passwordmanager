import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getTotp } from "./totp.js";

const API = import.meta.env.DEV ? "http://127.0.0.1:4173/api" : "/api";
const emptyEntry = { website: "", username: "", password: "", totpSecret: "", notes: "" };

async function request(path, { token, ...options } = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options?.headers
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Something went wrong.");
  return data;
}

export default function App() {
  const [configured, setConfigured] = useState(null);
  const [token, setToken] = useState("");
  const [records, setRecords] = useState([]);
  const [password, setPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(emptyEntry);
  const [notice, setNotice] = useState("");
  const [totpCodes, setTotpCodes] = useState({});
  const [generator, setGenerator] = useState("");
  const [visiblePasswords, setVisiblePasswords] = useState({});
  const clipboardTimer = useRef(null);

  const loadStatus = useCallback(async () => {
    const status = await request("/status");
    setConfigured(status.configured);
  }, []);

  useEffect(() => {
    loadStatus().catch((error) => setAuthError(error.message));
  }, [loadStatus]);

  const lock = useCallback(async () => {
    if (token) {
      try { await request("/lock", { method: "POST", token, body: "{}" }); } catch { /* local lock below */ }
    }
    setToken("");
    setRecords([]);
    setTotpCodes({});
    setPassword("");
  }, [token]);

  useEffect(() => {
    const onPageHide = () => {
      if (token) {
        fetch(`${API}/lock`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          keepalive: true
        }).catch(() => {});
      }
    };
    window.addEventListener("pagehide", onPageHide);
    return () => window.removeEventListener("pagehide", onPageHide);
  }, [token]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return records;
    return records.filter((record) =>
      [record.website, record.username, record.notes].some((value) =>
        value.toLowerCase().includes(query)
      )
    );
  }, [records, search]);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      const entries = records.filter((record) => record.totpSecret);
      const codes = {};
      await Promise.all(entries.map(async (entry) => {
        try { codes[entry.id] = await getTotp(entry.totpSecret); } catch { codes[entry.id] = "Invalid"; }
      }));
      if (active) setTotpCodes(codes);
    };
    if (token) {
      refresh();
      const timer = setInterval(refresh, 1000);
      return () => { active = false; clearInterval(timer); };
    }
    return () => { active = false; };
  }, [records, token]);

  async function authenticate(event) {
    event.preventDefault();
    setAuthError("");
    try {
      const result = await request(configured ? "/unlock" : "/setup", {
        method: "POST",
        body: JSON.stringify({ masterPassword: password })
      });
      setToken(result.token);
      setRecords(result.records);
      setPassword("");
      setConfigured(true);
    } catch (error) {
      setAuthError(error.message);
    }
  }

  async function saveRecords(next) {
    try {
      await request("/vault", { method: "PUT", token, body: JSON.stringify({ records: next }) });
      setRecords(next);
      setNotice("Vault saved");
      window.setTimeout(() => setNotice(""), 2200);
      return true;
    } catch (error) {
      setNotice(`Save failed: ${error.message}`);
      return false;
    }
  }

  function startAdd() {
    setEditing(null);
    setForm(emptyEntry);
    setGenerator("");
    setShowForm(true);
  }

  function startEdit(record) {
    setEditing(record.id);
    setForm({ ...record });
    setGenerator("");
    setShowForm(true);
  }

  async function submitEntry(event) {
    event.preventDefault();
    const entry = { ...form, id: editing || crypto.randomUUID() };
    const next = editing
      ? records.map((record) => record.id === editing ? entry : record)
      : [entry, ...records];
    if (await saveRecords(next)) setShowForm(false);
  }

  async function deleteEntry(id) {
    if (!window.confirm("Delete this saved account? This cannot be undone.")) return;
    await saveRecords(records.filter((record) => record.id !== id));
  }

  async function copySensitive(value, label) {
    try {
      await navigator.clipboard.writeText(value);
      if (clipboardTimer.current) clearTimeout(clipboardTimer.current);
      clipboardTimer.current = setTimeout(async () => {
        try {
          if (await navigator.clipboard.readText() === value) await navigator.clipboard.writeText("");
        } catch { /* browser clipboard read may require renewed permission */ }
      }, 30000);
      setNotice(`${label} copied · clears in 30 seconds`);
      window.setTimeout(() => setNotice(""), 3000);
    } catch {
      setNotice("Clipboard access was denied by the browser.");
    }
  }

  async function makePassword() {
    try {
      const result = await request("/generate-password", {
        method: "POST", token, body: JSON.stringify({ length: 20 })
      });
      setGenerator(result.password);
      setForm((current) => ({ ...current, password: result.password }));
    } catch (error) {
      setNotice(error.message);
    }
  }

  if (!token) {
    return (
      <main className="auth-page">
        <div className="brand-mark">H</div>
        <p className="eyebrow">YOUR PRIVATE SPACE</p>
        <h1>{configured ? "Welcome back." : "A safer place for your passwords."}</h1>
        <p className="auth-copy">
          Your vault is encrypted on this device. Your master password is never saved.
        </p>
        <form className="auth-card" onSubmit={authenticate}>
          <label htmlFor="master-password">{configured ? "Master password" : "Create a master password"}</label>
          <input
            id="master-password"
            autoFocus
            type="password"
            autoComplete={configured ? "current-password" : "new-password"}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            minLength={configured ? undefined : 14}
          />
          {!configured && <small>Use 14+ characters and at least three character types.</small>}
          {authError && <p className="error">{authError}</p>}
          <button className="primary full" type="submit">{configured ? "Unlock vault" : "Create encrypted vault"}</button>
        </form>
        <p className="fine-print">Local-first · AES-256-GCM · Argon2id · Auto-locks after 5 minutes</p>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark small">H</span><strong>haven</strong></div>
        <div className="side-label">YOUR VAULT</div>
        <button className="side-item selected"><span>▦</span> All items <span className="count">{records.length}</span></button>
        <div className="sidebar-bottom">
          <div className="secure-state"><span className="live-dot" /> Encrypted on this device</div>
          <button className="side-item lock-button" onClick={lock}><span>⌑</span> Lock vault</button>
        </div>
      </aside>
      <main className="main-content">
        <header className="topbar">
          <div><p className="eyebrow">YOUR PRIVATE SPACE</p><h1>Your vault</h1></div>
          <button className="primary" onClick={startAdd}>＋ <span>New login</span></button>
        </header>
        <section className="toolbar">
          <div className="search-wrap"><span>⌕</span><input aria-label="Search vault" placeholder="Search logins..." value={search} onChange={(event) => setSearch(event.target.value)} /></div>
          <div className="toolbar-note"><span className="live-dot" /> Saved locally</div>
        </section>
        {notice && <div className="notice" role="status">{notice}</div>}
        {records.length === 0 ? (
          <section className="empty-state">
            <div className="empty-icon">✳</div><h2>Your vault is ready</h2>
            <p>Add your first login. Everything is encrypted before it reaches your device storage.</p>
            <button className="primary" onClick={startAdd}>＋ Add your first login</button>
          </section>
        ) : filtered.length === 0 ? (
          <div className="no-results">No logins match “{search}”.</div>
        ) : (
          <section className="vault-grid" aria-label="Saved logins">
            {filtered.map((record) => (
              <article className="vault-card" key={record.id}>
                <div className="card-heading">
                  <div className="site-avatar">{(record.website || "?").trim().charAt(0).toUpperCase()}</div>
                  <div className="site-name"><h2>{record.website || "Untitled login"}</h2><p>{record.username || "No username"}</p></div>
                  <button className="icon-button" aria-label={`Edit ${record.website}`} onClick={() => startEdit(record)}>···</button>
                </div>
                <div className="secret-row">
                  <span className="field-label">PASSWORD</span>
                  <div className="secret-value">
                    <span>{visiblePasswords[record.id] ? record.password : "••••••••••••"}</span>
                    <button className="text-button" onClick={() => setVisiblePasswords((current) => ({ ...current, [record.id]: !current[record.id] }))}>{visiblePasswords[record.id] ? "Hide" : "Show"}</button>
                    <button className="text-button" onClick={() => copySensitive(record.password, "Password")}>Copy</button>
                  </div>
                </div>
                {record.totpSecret && <div className="totp-row">
                  <span className="field-label">TWO-FACTOR CODE</span>
                  <div className="totp-value"><strong>{totpCodes[record.id] || "··· ···"}</strong><button className="text-button" onClick={() => copySensitive(totpCodes[record.id] || "", "Code")}>Copy</button></div>
                </div>}
                <div className="card-actions">
                  <button className="text-button" onClick={() => startEdit(record)}>Edit</button>
                  <button className="text-button danger-text" onClick={() => deleteEntry(record.id)}>Delete</button>
                </div>
              </article>
            ))}
          </section>
        )}
        {records.length > 0 && <p className="results-count">{filtered.length} {filtered.length === 1 ? "login" : "logins"} {search && "found"}</p>}
      </main>

      {showForm && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setShowForm(false); }}>
        <form className="entry-modal" onSubmit={submitEntry}>
          <div className="modal-heading"><div><p className="eyebrow">VAULT ENTRY</p><h2>{editing ? "Edit login" : "New login"}</h2></div><button type="button" className="icon-button close-button" aria-label="Close" onClick={() => setShowForm(false)}>×</button></div>
          <label>Website or app<input autoFocus value={form.website} onChange={(event) => setForm({ ...form, website: event.target.value })} placeholder="example.com" maxLength="256" /></label>
          <label>Username or email<input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} autoComplete="off" maxLength="256" /></label>
          <label>Password<div className="password-input"><input value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} autoComplete="new-password" maxLength="4096" /><button type="button" className="text-button" onClick={makePassword}>Generate</button></div></label>
          <label>TOTP setup key <span className="optional">OPTIONAL · BASE32</span><input value={form.totpSecret} onChange={(event) => setForm({ ...form, totpSecret: event.target.value })} autoComplete="off" placeholder="JBSWY3DPEHPK3PXP" maxLength="256" /></label>
          <label>Notes <span className="optional">OPTIONAL</span><textarea rows="3" value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} maxLength="4096" /></label>
          {generator && <div className="generated-password"><span>Generated password</span><code>{generator}</code></div>}
          <div className="modal-actions"><button type="button" className="secondary" onClick={() => setShowForm(false)}>Cancel</button><button type="submit" className="primary">{editing ? "Save changes" : "Save login"}</button></div>
        </form>
      </div>}
    </div>
  );
}
