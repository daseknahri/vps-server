// vps-server/rotate-keys.js — issue a FRESH key for each existing client key (a security key-rotation helper).
// For each selected OLD key it MINTS a new key (same tier + expiry, UNBOUND so it binds to the client's machine on first
// activation), tags it "rotated from <old4>… — <old note>", and prints an OLD → NEW → note mapping + the revoke commands.
// It NEVER revokes the old keys and NEVER touches owner keys, so no seat is ever locked out mid-swap: you send the new key,
// the client activates, you confirm with list-keys, and ONLY THEN do you run the printed revoke.js on the old key.
//
//   node rotate-keys.js --all-clients                     # rotate every active, non-owner, non-revoked, non-expired key
//   node rotate-keys.js --all-clients --exclude=AAAA-...   # ...but skip these (e.g. your own laptop key), comma-separated
//   node rotate-keys.js --all-clients --dry-run            # preview only, write NOTHING
//   node rotate-keys.js KEY1 KEY2 ...                      # rotate just the listed keys (precise — recommended)
//
// Exit codes: 0 ok, 2 usage / nothing to do, 1 I/O error.
const crypto = require('crypto');
const ks = require('./keystore');

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const allClients = args.includes('--all-clients');
const excludeArg = args.find((a) => a.startsWith('--exclude='));
const excluded = new Set(excludeArg ? excludeArg.slice('--exclude='.length).split(',').map((k) => k.trim().toUpperCase()).filter(Boolean) : []);
const explicitKeys = args.filter((a) => !a.startsWith('--')).map((k) => k.trim().toUpperCase());

if (!allClients && explicitKeys.length === 0) {
  console.error('Usage:\n  node rotate-keys.js --all-clients [--exclude=KEY,KEY] [--dry-run]\n  node rotate-keys.js KEY1 KEY2 ... [--dry-run]');
  process.exit(2);
}

// Match gen-key.js EXACTLY: 8 random bytes → 16 hex → XXXX-XXXX-XXXX-XXXX.
function newKey() { return crypto.randomBytes(8).toString('hex').slice(0, 16).toUpperCase().match(/.{4}/g).join('-'); }

let db;
try { db = ks.load(); } catch (e) { console.error('Could not read the key store:', e.message); process.exit(1); }

const now = Date.now();
let targets;
if (allClients) {
  targets = Object.keys(db).filter((k) => {
    const r = db[k] || {};
    if (r.tier === 'owner') return false;              // NEVER rotate an owner key (offline master; can't be revoked anyway)
    if (r.revoked) return false;                       // already dead
    if (r.expires && now > r.expires) return false;    // already expired
    if (excluded.has(k)) return false;                 // operator opted this one out (e.g. their own laptop key)
    return true;
  });
} else {
  targets = explicitKeys.filter((k) => {
    if (!Object.prototype.hasOwnProperty.call(db, k)) { console.error('  skip (not found):', k); return false; }
    if (db[k].tier === 'owner') { console.error('  skip (owner key — never rotated):', k); return false; }
    return true;
  });
}

if (targets.length === 0) { console.error('No keys to rotate.'); process.exit(2); }

const mapping = [];
for (const oldKey of targets) {
  const oldRec = db[oldKey] || {};
  let nk = newKey();
  while (Object.prototype.hasOwnProperty.call(db, nk)) nk = newKey(); // 64-bit collision is astronomically unlikely, but never reuse a live key
  const rec = {
    hwid: null,                                        // UNBOUND → binds to the CLIENT's machine on first activation (never yours)
    revoked: false,
    expires: oldRec.expires || null,                   // preserve the old key's expiry (absolute)
    tier: oldRec.tier || 'standard',
    note: `rotated from ${oldKey.slice(0, 4)}… — ${oldRec.note || '(no note)'} (${new Date(now).toISOString().slice(0, 10)})`,
    createdAt: now,
  };
  if (!dryRun) db[nk] = rec;
  mapping.push({ oldKey, newKey: nk, tier: rec.tier, note: oldRec.note || '(no note)', expires: rec.expires });
}

if (!dryRun) {
  try { ks.save(db); for (const m of mapping) ks.audit('rotate', m.newKey, `rotated from ${m.oldKey.slice(0, 4)}… tier=${m.tier}`); }
  catch (e) { console.error('Could not write the key store:', e.message); process.exit(1); }
}

console.log(dryRun ? '\n=== DRY RUN (nothing written) ===' : '\n=== Rotated — new keys minted (old keys NOT revoked) ===');
for (const m of mapping) {
  console.log(`\n  ${m.note}`);
  console.log(`    OLD  ${m.oldKey}   (still active — revoke AFTER the client is live on the new key)`);
  console.log(`    NEW  ${m.newKey}   tier=${m.tier}  expires=${m.expires ? new Date(m.expires).toISOString().slice(0, 10) : 'never'}`);
}
console.log('\nNext steps — per client, IN THIS ORDER (no downtime):');
console.log('  1. Send the client their NEW key + the LATEST app zip you built for them over a SECURE channel.');
console.log('  2. They install it and activate → the new key binds to their machine.');
console.log('  3. Confirm:  node list-keys.js    (their NEW key shows bound + the new version)');
console.log('  4. THEN revoke the OLD key:');
for (const m of mapping) console.log(`       node revoke.js ${m.oldKey}`);
if (dryRun) console.log('\n(Re-run without --dry-run to actually mint the new keys.)');
