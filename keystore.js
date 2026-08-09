// vps-server/keystore.js
// Shared load/save/audit for the license key store, used by license-server.js, gen-key.js and
// revoke.js so all three agree on the on-disk format. When KEYS_ENCRYPTION_KEY is set the store is
// AES-256-GCM encrypted at rest (M3-05); otherwise it stays plaintext (back-compat). Env is read
// lazily so a process can point KEYS_PATH/KEYS_ENCRYPTION_KEY wherever it needs.
const fs = require('fs');
const path = require('path');
const kc = require('./crypto');

function keysPath() { return process.env.KEYS_PATH || path.join(__dirname, 'keys.json'); }
function encKey() { return process.env.KEYS_ENCRYPTION_KEY || ''; }
function isEncryptedAtRest() { return !!encKey(); }

// IN-MEMORY CACHE (2026-08-05 vps audit F1): validate() calls load() on EVERY request, and an encrypted store decrypts via
// crypto.scryptSync (CPU-hard, blocks the single-threaded event loop) — an UNAUTHENTICATED /api/validate flood could otherwise
// saturate the server. Cache the decrypted store keyed on the file's mtimeMs: an unchanged file serves the cached object (no
// re-read, no scrypt); an EXTERNAL write (gen-key/revoke/reset-hwid rename a NEW file → new mtime) falls through to a fresh
// read, so a revocation/new-key is NEVER served stale. save() refreshes the cache to exactly what it wrote. The cache holds the
// LIVE object by reference, so an in-place mutation (bind/lastSeen) is reflected without a re-read — correct because THIS server
// is the store's primary writer, and any writer that ISN'T this process changes the mtime.
let _cache = null, _cacheMtime = -1, _cacheFile = '';
function _invalidate() { _cache = null; _cacheMtime = -1; _cacheFile = ''; }
// Load the store. Returns {} only when the file does not exist yet (first run). A parse/decrypt
// failure THROWS — we must never silently treat a corrupt/wrong-key store as empty and overwrite it.
function load() {
  const file = keysPath();
  let st;
  try { st = fs.statSync(file); }
  catch (e) { if (e && e.code === 'ENOENT') { _invalidate(); return {}; } throw e; }
  if (_cache && _cacheFile === file && _cacheMtime === st.mtimeMs) return _cache;
  let txt;
  try { txt = fs.readFileSync(file, 'utf8'); }
  catch (e) { if (e && e.code === 'ENOENT') { _invalidate(); return {}; } throw e; }
  const raw = JSON.parse(txt);
  let db;
  if (kc.isEncrypted(raw)) {
    if (!encKey()) throw new Error('keys store is encrypted but KEYS_ENCRYPTION_KEY is not set');
    db = kc.decrypt(raw, encKey());
  } else db = (raw && typeof raw === 'object') ? raw : {};
  _cache = db; _cacheMtime = st.mtimeMs; _cacheFile = file;
  return db;
}

function save(db) {
  const file = keysPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const out = encKey() ? kc.encrypt(db, encKey()) : db;
  // Atomic-ish: write a temp file then rename so a crash mid-write can't truncate the store. PER-WRITER temp name
  // (pid+time+rand) so an admin running gen-key/revoke/reset-hwid WHILE the server is live can't clobber a shared
  // "<file>.tmp" and lose the other's update (2026-08-05 vps audit F8). The rename target is still the single canonical file.
  const tmp = file + '.tmp.' + process.pid + '.' + Date.now() + '.' + Math.floor(Math.random() * 1e9);
  try {
    fs.writeFileSync(tmp, JSON.stringify(out, null, 2));
    fs.renameSync(tmp, file);
  } catch (e) { try { fs.unlinkSync(tmp); } catch {} throw e; } // clean up our own temp on a failed write (unique name would otherwise orphan)
  // Refresh the load() cache to exactly what we just wrote → the next load() skips a re-read + scryptSync-decrypt (F1). On a
  // stat failure INVALIDATE (never keep a stale cache) so the next load() re-reads from disk.
  try { _cache = db; _cacheMtime = fs.statSync(file).mtimeMs; _cacheFile = file; } catch { _invalidate(); }
}

function auditPath() { return path.join(path.dirname(keysPath()), 'key-audit.log'); }
// Append a tamper-evident-ish audit line for key lifecycle events (create/bind/revoke/restore).
// The license is truncated so the log itself isn't a key dump.
function audit(event, license, detail) {
  try { fs.appendFileSync(auditPath(), JSON.stringify({ ts: new Date().toISOString(), event, key: String(license || '').slice(0, 4) + '…', detail: detail || '' }) + '\n'); } catch {}
}

module.exports = { load, save, audit, keysPath, isEncryptedAtRest };
