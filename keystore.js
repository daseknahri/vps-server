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
let _cache = null, _cacheMtime = -1, _cacheFile = '', _cacheSize = -1, _cacheIno = -1;
function _invalidate() { _cache = null; _cacheMtime = -1; _cacheFile = ''; _cacheSize = -1; _cacheIno = -1; }
// Load the store. Returns {} only when the file does not exist yet (first run). A parse/decrypt
// failure THROWS — we must never silently treat a corrupt/wrong-key store as empty and overwrite it.
function load() {
  const file = keysPath();
  let st;
  try { st = fs.statSync(file); }
  catch (e) { if (e && e.code === 'ENOENT') { _invalidate(); return {}; } throw e; }
  // ★2026-08-16: key the cache on mtime AND size AND inode, not mtime alone. On a coarse-mtime volume (some network/overlay
  // drivers, ≥1s granularity) an external admin write (revoke/suspend/extend — each an atomic rename → NEW inode) can land in
  // the SAME mtime tick as the server's last save; keying on mtime alone would serve the STALE record and miss the revoke —
  // worse, the server would then re-persist the stale copy over it. size+ino perturb on any real external write → re-read.
  if (_cache && _cacheFile === file && _cacheMtime === st.mtimeMs && _cacheSize === st.size && _cacheIno === st.ino) return _cache;
  let txt;
  try { txt = fs.readFileSync(file, 'utf8'); }
  catch (e) { if (e && e.code === 'ENOENT') { _invalidate(); return {}; } throw e; }
  const raw = JSON.parse(txt);
  let db;
  if (kc.isEncrypted(raw)) {
    if (!encKey()) throw new Error('keys store is encrypted but KEYS_ENCRYPTION_KEY is not set');
    db = kc.decrypt(raw, encKey());
  } else db = (raw && typeof raw === 'object') ? raw : {};
  _cache = db; _cacheMtime = st.mtimeMs; _cacheFile = file; _cacheSize = st.size; _cacheIno = st.ino;
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
  try { const _st = fs.statSync(file); _cache = db; _cacheMtime = _st.mtimeMs; _cacheFile = file; _cacheSize = _st.size; _cacheIno = _st.ino; } catch { _invalidate(); }
}

function auditPath() { return path.join(path.dirname(keysPath()), 'key-audit.log'); }
// Append a tamper-evident-ish audit line for key lifecycle events (create/bind/revoke/restore).
// The license is truncated so the log itself isn't a key dump.
function audit(event, license, detail) {
  try { fs.appendFileSync(auditPath(), JSON.stringify({ ts: new Date().toISOString(), event, key: String(license || '').slice(0, 4) + '…', detail: detail || '' }) + '\n'); } catch {}
}

// ★RANK-2 (2026-08-15): server-side clone detection. The CLIENT device-lock cannot catch a MachineGuid CLONE — every copy
// presents the SAME bound hwid, so /api/validate's `rec.hwid !== hwid` check passes for all of them. But a cloned key
// validates from MANY IPs where one honest seat uses ~1. This records recent distinct IPs per key in a bounded, time-windowed
// log; the caller FLAGS (never auto-denies — a roaming/mobile/VPN customer legitimately spans IPs) when the fan-out is high,
// for operator review + manual revoke. PURE (mutates rec.ipLog in place, no I/O) → unit-tested. Returns the current fan-out.
function recordValidationIp(rec, ip, now, opts) {
  opts = opts || {};
  const windowMs = Number(opts.windowMs) || 24 * 3600 * 1000;
  const maxLog = Number(opts.maxLog) || 50;
  if (!rec || !ip) return { distinct: 0, isNew: false };
  let log = Array.isArray(rec.ipLog) ? rec.ipLog.filter((e) => e && e.ip && (now - Number(e.ts) <= windowMs)) : [];
  const isNew = !log.some((e) => e.ip === ip);
  if (isNew) log.push({ ip: String(ip), ts: now });
  if (log.length > maxLog) log = log.slice(-maxLog);
  rec.ipLog = log;
  return { distinct: new Set(log.map((e) => e.ip)).size, isNew };
}

// ★VERSION GATE (2026-08-15): compare two dotted numeric versions. Returns true iff a < b. Tolerant of missing parts +
// non-numeric segments (treated as 0) and never throws — a garbled version string must never gate a legit client (the
// caller only gates when BOTH the client version AND the required minimum are present + parse to real numbers).
function semverLt(a, b) {
  const pa = String(a == null ? '' : a).split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b == null ? '' : b).split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] || 0, dbv = pb[i] || 0;
    if (da < dbv) return true;
    if (da > dbv) return false;
  }
  return false; // equal → not less-than
}

// ★2026-08-15 per-brand telemetry aggregation. ONE client runs all 4 brand-apps (same key, separate userData each); each
// reports its OWN account/group counts, so store them PER BRAND and let the reader SUM → a combined per-client total.
// `brand` is client-controlled and becomes an object key → sanitize HARD: strip to [a-z0-9-] (removing the underscores that
// make __proto__ dangerous), cap length, and reject the pollution names. Prunes brands unseen for `staleMs`. Returns the
// safe brand stored, or null if the brand was empty/rejected (the caller then keeps flat single-app telemetry for old clients).
function recordAppTelemetry(rec, brand, info, now, opts) {
  if (!rec) return null;
  opts = opts || {}; info = info || {};
  const staleMs = Number(opts.staleMs) || 14 * 86400000;
  const sb = String(brand == null ? '' : brand).replace(/[^a-z0-9-]/gi, '').slice(0, 40).toLowerCase();
  if (!sb || sb === '__proto__' || sb === 'constructor' || sb === 'prototype') return null;
  if (!rec.apps || typeof rec.apps !== 'object') rec.apps = {};
  const prev = rec.apps[sb] || {};
  rec.apps[sb] = { ver: info.ver || prev.ver || '', acc: Number(info.acc) || 0, grp: Number(info.grp) || 0, at: now };
  for (const b of Object.keys(rec.apps)) { if (!rec.apps[b] || (now - Number(rec.apps[b].at || 0)) > staleMs) delete rec.apps[b]; }
  // HARDENING: cap the brand count so a malicious client spamming many distinct brands can't bloat the keystore (a real
  // client runs ≤4 brands; 16 tolerates renames/churn). Drop the OLDEST beyond the cap — but never the one just written.
  const MAX = Number(opts.maxBrands) || 16, bs = Object.keys(rec.apps);
  if (bs.length > MAX) { bs.sort((a, b) => Number(rec.apps[a].at || 0) - Number(rec.apps[b].at || 0)); for (const b of bs.slice(0, bs.length - MAX)) { if (b !== sb) delete rec.apps[b]; } }
  return sb;
}
// Sum accounts + groups across a key's brand-apps → the COMBINED per-client total. Falls back to the flat lastAccounts/
// lastGroups for an older client that never reported a brand. Pure read.
function sumAppTelemetry(rec) {
  rec = rec || {};
  if (rec.apps && typeof rec.apps === 'object') {
    let acc = 0, grp = 0, n = 0;
    for (const b of Object.keys(rec.apps)) { const a = rec.apps[b] || {}; acc += Number(a.acc) || 0; grp += Number(a.grp) || 0; n++; }
    return { acc, grp, apps: n };
  }
  return { acc: Number(rec.lastAccounts) || 0, grp: Number(rec.lastGroups) || 0, apps: 0 };
}

module.exports = { load, save, audit, keysPath, isEncryptedAtRest, recordValidationIp, semverLt, recordAppTelemetry, sumAppTelemetry };
