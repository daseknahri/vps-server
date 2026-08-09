// vps-server/list-keys.js — list ALL license keys + their state (tier, expiry, machine binding, revoked, note).
//   node list-keys.js
// Read-only. Exit codes: 0 = ok, 1 = I/O error.
const ks = require('./keystore');

let db;
try { db = ks.load(); } catch (e) { console.error('Could not read the key store:', e.message); process.exit(1); }

const keys = Object.keys(db);
if (!keys.length) { console.log('(no keys in the store yet)'); process.exit(0); }

const now = Date.now();
const day = (ms) => ms ? new Date(ms).toISOString().slice(0, 10) : null;
let active = 0, expired = 0, revoked = 0, unbound = 0;
console.log(keys.length + ' key(s):\n');
for (const k of keys.sort()) {
  const r = db[k] || {};
  const isExpired = r.expires && r.expires < now;
  if (r.revoked) revoked++; else if (isExpired) expired++; else active++;
  if (!r.hwid) unbound++;
  const exp = r.expires ? (isExpired ? 'EXPIRED ' + day(r.expires) : 'expires ' + day(r.expires)) : 'no expiry';
  console.log('  ' + k
    + '  | ' + String(r.tier || 'standard').padEnd(8)
    + ' | ' + (r.revoked ? 'REVOKED' : (isExpired ? 'expired' : 'active ')).padEnd(7)
    + ' | ' + (r.hwid ? 'bound(' + String(r.hwid).slice(0, 10) + '…)' : 'UNBOUND        ')
    + ' | ' + exp
    + (r.note ? '  | ' + r.note : ''));
}
console.log('\nsummary: ' + active + ' active, ' + expired + ' expired, ' + revoked + ' revoked | ' + unbound + ' unbound (free to activate on a new machine)');
