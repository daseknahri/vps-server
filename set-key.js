// vps-server/set-key.js — set the operator-controlled fields the server READS at /api/validate but no admin script WRITES today:
//   --message "text"      a soft notice shown to the client on its next check (nag WITHOUT suspending; server reads rec.message)
//   --min-version 1.0.293 a PER-KEY minimum client version — retire ONE leaked/old build without touching the fleet-wide
//                         MIN_CLIENT_VERSION env (which needs a VPS redeploy). The client treats 'outdated' as a soft nag +
//                         offline-grace, NOT an instant lockout (lib/license.js), so this is control, not a brick.
//   --tier standard|pro|trial   change the tier (tier rides the SIGNED grant → real, not spoofable). owner is refused here.
//   --note "Client Name"  the display note in list-keys.js
//   --clear-message / --clear-min-version   unset either field
//   node set-key.js AAAA-BBBB-CCCC-DDDD --message "Renew by Oct 1" --min-version 1.0.293
// CAS-safe (ks.mutate). Exit codes: 0 = ok, 2 = usage / key-not-found / bad arg, 1 = I/O error.
const ks = require('./keystore');
const SET_TIERS = new Set(['trial', 'standard', 'pro']); // owner is DELIBERATELY excluded — an owner key is an unrevocable master; mint one only via gen-key, never by promoting a customer key here

const args = process.argv.slice(2);
const key = String(args[0] || '').trim().toUpperCase();
if (!key || key.startsWith('--')) { console.error('Usage: node set-key.js <KEY> [--message "..."] [--min-version 1.0.293] [--tier pro] [--note "..."] [--clear-message] [--clear-min-version]'); process.exit(2); }
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const has = (name) => args.includes(name);

const message = opt('--message'), minVersion = opt('--min-version'), tier = opt('--tier'), note = opt('--note');
if (tier !== undefined && !SET_TIERS.has(String(tier).toLowerCase())) { console.error('--tier must be one of: ' + [...SET_TIERS].join(', ') + ' (owner keys are minted only via gen-key)'); process.exit(2); }
if (minVersion !== undefined && !/^\d+(\.\d+){0,3}$/.test(String(minVersion))) { console.error('--min-version must be a dotted version like 1.0.293'); process.exit(2); }

let found = true; const changed = [];
try {
  ks.mutate((db) => {
    changed.length = 0; // reset so a CAS re-apply doesn't duplicate entries (idempotent contract)
    if (!db[key]) { found = false; return; }
    found = true;
    const r = db[key];
    if (message !== undefined) { r.message = String(message).slice(0, 300); changed.push('message'); }
    if (has('--clear-message')) { delete r.message; changed.push('message=cleared'); }
    if (minVersion !== undefined) { r.minVersion = String(minVersion); changed.push('minVersion=' + r.minVersion); }
    if (has('--clear-min-version')) { delete r.minVersion; changed.push('minVersion=cleared'); }
    if (tier !== undefined) { r.tier = String(tier).toLowerCase(); changed.push('tier=' + r.tier); }
    if (note !== undefined) { r.note = String(note).slice(0, 200); changed.push('note'); }
  });
} catch (e) { console.error('Could not write the key store:', e.message); process.exit(1); }

if (!found) { console.error('Key not found:', key); process.exit(2); }
if (!changed.length) { console.error('Nothing to change — pass at least one of --message / --min-version / --tier / --note / --clear-message / --clear-min-version'); process.exit(2); }
try { ks.audit('set-key', key, changed.join(' ')); } catch {}
console.log(key, '-> updated:', changed.join(', '));
