// vps-server/suspend.js — SUSPEND (or lift) a license key. A reversible, gentler kill than revoke: the seat is denied at
// its next online check with a message, but the record + machine binding are PRESERVED, so lifting it restores the seat
// instantly. Use after reviewing a ⚠️ multi-IP CLONE flag (list-keys.js) to stop a confirmed share WITHOUT permanently
// revoking a customer you might reinstate.
//   node suspend.js AAAA-BBBB-CCCC-DDDD                                   (suspend)
//   node suspend.js AAAA-BBBB-CCCC-DDDD --reason "shared on 8 machines"   (suspend + a custom message shown to the client)
//   node suspend.js AAAA-BBBB-CCCC-DDDD --lift                            (un-suspend → the seat works again on its next check)
// Exit codes: 0 = ok, 2 = usage / key-not-found, 1 = I/O error.
const ks = require('./keystore');

const key = String(process.argv[2] || '').trim().toUpperCase();
if (!key) { console.error('Usage: node suspend.js <KEY> [--reason "text"] [--lift]'); process.exit(2); }

let db;
try { db = ks.load(); }
catch (e) { console.error('Could not read the key store:', e.message); process.exit(1); }

if (!db[key]) { console.error('Key not found:', key); process.exit(2); }

const lift = process.argv.includes('--lift');
const _ri = process.argv.indexOf('--reason');
const reason = (_ri >= 0 && process.argv[_ri + 1]) ? String(process.argv[_ri + 1]).slice(0, 200) : '';

if (lift) { db[key].suspended = false; db[key].suspendMessage = ''; }
else { db[key].suspended = true; if (reason) db[key].suspendMessage = 'License suspended — ' + reason; }

try { ks.save(db); ks.audit(lift ? 'unsuspend' : 'suspend', key, reason); }
catch (e) { console.error('Could not write the key store:', e.message); process.exit(1); }

console.log(key, '->', db[key].suspended ? 'SUSPENDED' : 'active', db[key].suspendMessage ? '("' + db[key].suspendMessage + '")' : '');
if (db[key].suspended) console.log('ℹ️  Denied at the seat\'s next ONLINE check (it runs offline until its grace expires, same as revoke). Reinstate anytime with --lift — the binding is preserved, so it activates instantly.');
