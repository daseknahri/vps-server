// vps-server/extend-keys.js — BULK-extend the expiry of license keys to N days FROM NOW (default 365 = one year).
//   node extend-keys.js                 (ALL keys → 1 year from now)
//   node extend-keys.js 365             (ALL keys → 365 days from now)
//   node extend-keys.js 365 AAAA-BBBB-CCCC-DDDD   (only that one key)
//   node extend-keys.js 0               (ALL keys → NO expiry / perpetual)
//   node extend-keys.js 365 --include-revoked     (also touch revoked keys)
// Only ever changes `expires`; never touches hwid / tier / revoked. Revoked keys are SKIPPED unless --include-revoked.
// Exit codes: 0 = ok, 2 = usage / key-not-found, 1 = I/O error.
const ks = require('./keystore');

const days = parseInt(process.argv[2] != null && !String(process.argv[2]).startsWith('--') ? process.argv[2] : '365', 10);
if (Number.isNaN(days) || days < 0) { console.error('Usage: node extend-keys.js [days>=0] [KEY] [--include-revoked]   (0 = no expiry)'); process.exit(2); }
const only = (process.argv[3] && !String(process.argv[3]).startsWith('--')) ? String(process.argv[3]).trim().toUpperCase() : null;
const includeRevoked = process.argv.includes('--include-revoked');

let db;
try { db = ks.load(); } catch (e) { console.error('Could not read the key store:', e.message); process.exit(1); }

const newExp = days > 0 ? Date.now() + days * 86400000 : null;
let n = 0, skipped = 0;
for (const k of Object.keys(db)) {
  if (only && k !== only) continue;
  const r = db[k]; if (!r) continue;
  if (r.revoked && !includeRevoked) { skipped++; continue; }
  r.expires = newExp; n++;
}
if (only && n === 0) { console.error('Key not found (or it is revoked — add --include-revoked):', only); process.exit(2); }

try { ks.save(db); ks.audit('extend', only || '(all)', days > 0 ? days + 'd → ' + new Date(newExp).toISOString().slice(0, 10) : 'no-expiry'); }
catch (e) { console.error('Could not write the key store:', e.message); process.exit(1); }

console.log('Extended ' + n + ' key(s) → ' + (newExp ? 'expires ' + new Date(newExp).toISOString().slice(0, 10) : 'NO expiry (perpetual)')
  + (skipped ? '  (' + skipped + ' revoked key(s) skipped — add --include-revoked to touch them)' : ''));
