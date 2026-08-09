// vps-server/reset-keys.js — START FRESH: back up the store, DELETE every non-owner key, then issue ONE new key per client.
//   node reset-keys.js "Client A" "Client B" "Client C"
//   node reset-keys.js --days 365 --tier pro "Client A" "Client B"
// Backs up to keys.backup-<ts>.json FIRST (restore by copying it back over keys.json). Any tier:'owner' key is KEPT (that's your
// admin key). New keys default to 1-year 'pro', UNBOUND (each client's machine binds it on first launch). Prints "name -> KEY".
// Exit codes: 0 = ok, 2 = usage, 1 = I/O error (nothing is deleted unless the backup wrote first).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ks = require('./keystore');
const TIERS = new Set(['trial', 'standard', 'pro', 'owner']);

const args = process.argv.slice(2);
let days = 365, tier = 'pro';
const names = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--days') days = parseInt(args[++i], 10);
  else if (args[i] === '--tier') tier = String(args[++i] || '').toLowerCase();
  else names.push(args[i]);
}
if (!names.length) { console.error('Usage: node reset-keys.js [--days 365] [--tier pro] "Client A" "Client B" …'); process.exit(2); }
if (Number.isNaN(days) || days < 0) { console.error('--days must be >= 0 (0 = no expiry)'); process.exit(2); }
if (!TIERS.has(tier)) { console.error('--tier must be one of: ' + [...TIERS].join(', ')); process.exit(2); }

let db;
try { db = ks.load(); } catch (e) { console.error('Could not read the key store:', e.message); process.exit(1); }

// Back up FIRST — a plaintext snapshot so a mistake is reversible. Abort (delete nothing) if the backup can't be written.
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const bak = path.join(path.dirname(ks.keysPath()), 'keys.backup-' + stamp + '.json');
try { fs.writeFileSync(bak, JSON.stringify(db, null, 2)); }
catch (e) { console.error('Could not write the backup — ABORTING, nothing deleted:', e.message); process.exit(1); }

// Delete every NON-owner key.
let deleted = 0;
for (const k of Object.keys(db)) { if ((db[k] && db[k].tier) === 'owner') continue; delete db[k]; deleted++; }

// Issue one new key per client name (same key shape as gen-key.js).
const issued = [];
for (const note of names) {
  const key = crypto.randomBytes(8).toString('hex').slice(0, 16).toUpperCase().match(/.{4}/g).join('-');
  db[key] = { hwid: null, revoked: false, expires: days > 0 ? Date.now() + days * 86400000 : null, tier, note: note || '', createdAt: Date.now() };
  issued.push([note, key]);
}

try { ks.save(db); ks.audit('reset-keys', '(all)', 'deleted ' + deleted + ' → issued ' + issued.length); }
catch (e) { console.error('Could not write the key store:', e.message, '\nYour backup is safe at', bak); process.exit(1); }

console.log('Backed up to: ' + bak);
console.log('Deleted ' + deleted + ' non-owner key(s). Issued ' + issued.length + ' new key(s) (' + tier + ', ' + (days > 0 ? days + ' days' : 'no expiry') + '):\n');
for (const [note, key] of issued) console.log('  ' + String(note || '(unnamed)').padEnd(24) + '  →  ' + key);
console.log('\nSend each client THEIR key. It is UNBOUND → it binds to their machine on first launch.');
console.log('⚠️  Do NOT launch a client key on your own PC (that binds it to you — use reset-hwid.js if you do).');
