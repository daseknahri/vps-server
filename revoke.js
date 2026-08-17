// vps-server/revoke.js — revoke (or un-revoke) a license key.
//   node revoke.js AAAA-BBBB-CCCC-DDDD            (revoke)
//   node revoke.js AAAA-BBBB-CCCC-DDDD --unbind   (revoke + clear machine binding so it can re-activate)
//   node revoke.js AAAA-BBBB-CCCC-DDDD --restore  (un-revoke)
// Exit codes: 0 = ok, 2 = usage / key-not-found, 1 = I/O error (so CI/scripts can tell them apart).
const ks = require('./keystore');

const key = String(process.argv[2] || '').trim().toUpperCase();
if (!key) { console.error('Usage: node revoke.js <KEY> [--unbind] [--restore]'); process.exit(2); }

let db;
try { db = ks.load(); }
catch (e) { console.error('Could not read the key store:', e.message); process.exit(1); }

if (!db[key]) { console.error('Key not found:', key); process.exit(2); }

const restore = process.argv.includes('--restore');
const unbind = process.argv.includes('--unbind');
db[key].revoked = !restore;
if (unbind) db[key].hwid = null;

try { ks.save(db); ks.audit(restore ? 'restore' : 'revoke', key, unbind ? 'unbind' : ''); }
catch (e) { console.error('Could not write the key store:', e.message); process.exit(1); }

console.log(key, '->', db[key].revoked ? 'REVOKED' : 'active', db[key].hwid ? '(bound)' : '(unbound)');
// REVOKE is the KILL SWITCH: on the seat's next ONLINE check (launch / hourly re-validate) the client sees `revoked`, DELETES its
// cached licence, and locks immediately — so it can't come back. Prefer this to DELETING the key (reset-keys.js): a deleted key
// returns a plain "invalid" that does NOT wipe the client cache, so an already-activated machine can keep running OFFLINE on its
// cached signed token until its 7-day grace runs out. Neither can kill a CURRENTLY-offline machine instantly (offline grace is
// inherent) — revoke ends it the moment that machine next touches the internet.
if (!db[key].revoked) console.log('ℹ️  (un-revoked. To KILL a seat, revoke it — that wipes the client cache on its next online check; deleting the key alone leaves a ~7-day offline tail.)');
