// vps-server/clear-flag.js — clear a stale review flag (and optionally re-baseline the seat) on a license key.
// A ⚠️ flag (multi-ip / multi-hwid / multi-instance-rate / seat-mismatch) is written on review-worthy activity but is NEVER
// cleared automatically anywhere in the codebase — so a roaming customer who tripped multi-ip once, or EVERY key after a
// version rebuild (seat-mismatch, when SEAT_ID is unset → a fresh random watermark each build), stays ⚠️-flagged in
// list-keys.js forever. This clears rec.flagged so the review list is honest again. --reset-seat also drops the seatClient/
// lastSeat baseline so the NEXT activation re-learns the current build's seat — use it AFTER adopting a stable per-customer
// SEAT_ID, so the key re-baselines to the new stable watermark instead of re-flagging against the old random one.
//   node clear-flag.js AAAA-BBBB-CCCC-DDDD              (clear the review flag)
//   node clear-flag.js AAAA-BBBB-CCCC-DDDD --reset-seat (also drop the seat baseline → re-learned on next activation)
// CAS-safe (ks.mutate) so it can't clobber a concurrent live-server write. Clears metadata only — touches no enforcement path.
// Exit codes: 0 = ok, 2 = usage / key-not-found, 1 = I/O error.
const ks = require('./keystore');

const key = String(process.argv[2] || '').trim().toUpperCase();
if (!key) { console.error('Usage: node clear-flag.js <KEY> [--reset-seat]'); process.exit(2); }
const resetSeat = process.argv.includes('--reset-seat');

let found = true, had = '(none)';
try {
  ks.mutate((db) => {
    // Idempotent under CAS re-apply: pure overwrites + deletes, no accumulation, no per-run randomness.
    if (!db[key]) { found = false; return; }
    found = true;
    const r = db[key];
    had = (r.flagged && r.flagged.reason) || '(none)';
    delete r.flagged;
    if (resetSeat) { delete r.seatClient; delete r.lastSeat; }
  });
} catch (e) { console.error('Could not write the key store:', e.message); process.exit(1); }

if (!found) { console.error('Key not found:', key); process.exit(2); }
try { ks.audit('clear-flag', key, 'was=' + had + (resetSeat ? ' +reset-seat' : '')); } catch {}
console.log(key, '-> flag cleared (was: ' + had + ')' + (resetSeat ? '; seat baseline reset — re-learned on next activation' : ''));
