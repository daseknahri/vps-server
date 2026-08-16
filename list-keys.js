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
let active = 0, expired = 0, revoked = 0, unbound = 0, flagged = 0, suspended = 0;
console.log(keys.length + ' key(s):\n');
for (const k of keys.sort()) {
  const r = db[k] || {};
  const isExpired = r.expires && r.expires < now;
  if (r.revoked) revoked++; else if (isExpired) expired++; else active++;
  if (!r.hwid) unbound++;
  const _flag = r.flagged && /^(multi-ip|multi-hwid|multi-instance-rate)$/.test(r.flagged.reason); if (_flag) flagged++; // ★RANK-2/2b: server-side clone signals (IP fan-out, second-machine hwid, same-hwid rate)
  if (r.suspended) suspended++; // ★2026-08-15: operator-suspended seat
  const exp = r.expires ? (isExpired ? 'EXPIRED ' + day(r.expires) : 'expires ' + day(r.expires)) : 'no expiry';
  // ★telemetry: SUM accounts + groups across the client's brand-apps (rec.apps) → the COMBINED per-client total; fall back
  // to the flat lastAccounts/lastGroups for an older client that reports no brand.
  const _t = ks.sumAppTelemetry(r); const _acc = _t.acc, _grp = _t.grp, _nApps = _t.apps;
  const tele = (r.lastVersion || _acc || _grp) ? ('  | ' + (r.lastVersion ? 'v' + r.lastVersion : 'v?') + (_acc ? ' ' + _acc + 'acct' : '') + (_grp ? ' ' + _grp + 'grp' : '') + (_nApps > 1 ? ' (' + _nApps + ' apps)' : '')) : ''; // combined across brand-apps
  console.log('  ' + k
    + '  | ' + String(r.tier || 'standard').padEnd(8)
    + ' | ' + (r.suspended ? 'SUSPEND' : (r.revoked ? 'REVOKED' : (isExpired ? 'expired' : 'active '))).padEnd(7)
    + ' | ' + (r.hwid ? 'bound(' + String(r.hwid).slice(0, 10) + '…)' : 'UNBOUND        ')
    + ' | ' + exp
    + tele
    + (r.note ? '  | ' + r.note : '')
    + (_flag ? '  | ⚠️ CLONE? ' + (r.flagged.reason === 'multi-ip' ? r.flagged.ips + ' IPs/24h' : r.flagged.reason === 'multi-hwid' ? r.flagged.hwids + ' machines' : 'rate ' + r.flagged.hits) + ' — review, then suspend.js/revoke.js if shared' : ''));
}
console.log('\nsummary: ' + active + ' active, ' + expired + ' expired, ' + revoked + ' revoked'
  + (suspended ? ', ' + suspended + ' suspended' : '') + ' | ' + unbound + ' unbound (free to activate on a new machine)'
  + (flagged ? '\n⚠️  ' + flagged + ' key(s) FLAGGED for multi-IP fan-out (possible MachineGuid clones) — review, then `node revoke.js <key>` if shared.' : ''));
