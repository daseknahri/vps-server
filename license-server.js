// vps-server/license-server.js
// License validation server for "Za Post Comment Tool". Deploy on your VPS BEHIND AN HTTPS PROXY
// (Coolify/Traefik terminate TLS — see DEPLOY-COOLIFY.md). The desktop app POSTs here on activation
// and on each launch. Pairs with the client in ../lib/license.js.
//
//   npm i express                                    (on the VPS)
//   ADMIN_TOKEN=secret KEYS_ENCRYPTION_KEY=secret2 node license-server.js
//
// Endpoints:
//   GET  /health                              -> 200 { ok:true }                (no auth)
//   POST /api/validate  { license, hwid }     -> { valid, revoked?, tier, maxAccounts, maxGroups, expires }
//   GET  /api/keys                            -> the key store (admin: Authorization: Bearer <ADMIN_TOKEN>)

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const ks = require('./keystore');

// ── LICENCE SIGNING KEY ──────────────────────────────────────────────────────────────────────────────────────────────
// The client refuses any grant that is not signed by this key, so an unsigned server is a server that activates
// nobody. Load it from LICENSE_SIGNING_KEY (base64 of the PKCS8 PEM) or ./signing-key.pem, and REFUSE TO BOOT if it
// is missing: a server that will not start is loudly broken and gets noticed during deploy, whereas one that quietly
// serves unsigned grants would look healthy while every customer drifted into lockout as their grace ran out.
// Never auto-generate — the public half is compiled into shipped clients, so the pair must be fixed and deliberate.
const PEM_RE = /BEGIN (PRIVATE|ED25519 PRIVATE) KEY/;
// Find the variable even if its NAME was typed slightly wrong. Coolify's env editor happily accepts a trailing
// space, and this project's own prose spells it "licence" (British) while the variable is LICENSE_ (American) —
// so LICENCE_SIGNING_KEY and "LICENSE_SIGNING_KEY " are the two mistakes practically begging to be made. Both
// look identical to "variable absent" from inside the process, which is a brutal thing to debug through redeploys.
function findSigningKeyVar() {
  if (String(process.env.LICENSE_SIGNING_KEY || '').trim()) return { value: process.env.LICENSE_SIGNING_KEY.trim(), name: 'LICENSE_SIGNING_KEY' };
  for (const k of Object.keys(process.env)) {
    if (/^\s*licen[sc]e[_-]?signing[_-]?key\s*$/i.test(k) && String(process.env[k] || '').trim()) {
      return { value: String(process.env[k]).trim(), name: k };
    }
  }
  return { value: '', name: null };
}

function loadSigningKey() {
  const found = findSigningKeyVar();
  const raw = found.value;
  if (found.name && found.name !== 'LICENSE_SIGNING_KEY') {
    console.warn(`WARNING: using env var ${JSON.stringify(found.name)} — rename it to exactly LICENSE_SIGNING_KEY.`);
  }
  let pem = null, how = '';
  if (raw) {
    // Accept the key HOWEVER it was pasted. Coolify's env editor is a single-line field, so the same key arrives
    // base64-encoded (what gen-signing-key.js prints), pasted raw with real newlines, or flattened with literal
    // \n sequences. All are the identical key — rejecting some of them just burns deploy cycles.
    // HEX is offered too because it is the only encoding with no +, / or = in it: base64 padding has a habit of
    // being mangled or dropped by env-var editors and .env parsers, and that failure is invisible from outside.
    const tries = [
      ['raw PEM', () => (PEM_RE.test(raw) ? raw.replace(/\\n/g, '\n') : null)],
      ['base64', () => Buffer.from(raw, 'base64').toString('utf8')],
      ['hex', () => (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0 ? Buffer.from(raw, 'hex').toString('utf8') : null)],
    ];
    for (const [label, decode] of tries) {
      try { const d = decode(); if (d && PEM_RE.test(d)) { pem = d; how = `LICENSE_SIGNING_KEY (${label})`; break; } } catch {}
    }
  }
  // File fallbacks, in case the environment itself is the problem. /data is the persistent volume this server
  // already mounts for keys.json, so a key placed there survives redeploys without going near an env editor.
  if (!pem) {
    const candidates = [
      [String(process.env.LICENSE_SIGNING_KEY_FILE || '').trim(), 'LICENSE_SIGNING_KEY_FILE'],
      ['/data/signing-key.pem', '/data/signing-key.pem (persistent volume)'],
      [path.join(__dirname, 'signing-key.pem'), 'signing-key.pem beside the server'],
    ];
    for (const [f, label] of candidates) {
      try { if (f && fs.existsSync(f)) { const t = fs.readFileSync(f, 'utf8'); if (PEM_RE.test(t)) { pem = t; how = label; break; } } } catch {}
    }
  }
  if (!pem) {
    // Name WHICH failure this is. "Variable absent" and "variable set but not a key" look identical from outside
    // the container and have completely different fixes; guessing wrong costs a full redeploy each time.
    console.error('\nFATAL: no licence signing key.');
    console.error(raw
      ? `  LICENSE_SIGNING_KEY is SET (${raw.length} chars) but is neither base64-of-a-PEM nor a PEM itself.\n` +
        '  Most likely truncated on paste, or the wrong value was copied. Expect ~160 chars of base64 for an\n' +
        '  Ed25519 PKCS8 key, or a full -----BEGIN PRIVATE KEY----- block.'
      : '  LICENSE_SIGNING_KEY is EMPTY or absent from this container, and no key file was found at\n' +
        '  LICENSE_SIGNING_KEY_FILE, /data/signing-key.pem, or beside this server.\n' +
        '  In Coolify: set it on THIS resource as a RUNTIME variable (a build-only variable never reaches the\n' +
        '  running process), Save, then Redeploy — restarting alone does not re-read the environment.\n' +
        '  If the variable still will not stick, sidestep the env editor entirely: put the PEM at\n' +
        '  /data/signing-key.pem on the persistent volume, or paste the key as HEX (no +, / or = to mangle).');
    // Print what this PROCESS can actually see. Names are JSON-quoted so a trailing space or stray character is
    // visible; values are never printed, only their length. Guessing at this from outside has cost several
    // redeploy cycles, and the running process is the only witness that cannot be wrong.
    const near = Object.keys(process.env).filter((k) => /lic|sign|key/i.test(k)).sort();
    console.error('  Env vars this process can see matching lic/sign/key:');
    console.error(near.length
      ? near.map((k) => `    ${JSON.stringify(k)} = <${String(process.env[k] || '').length} chars>`).join('\n')
      : '    (none — nothing resembling the variable reached this container at all)');
    console.error('  Generate a pair with:  node gen-signing-key.js');
    console.error('  The PUBLIC half must match LICENSE_PUBKEY compiled into the client, or nobody can activate.\n');
    process.exit(1);
  }
  try {
    const k = crypto.createPrivateKey(pem);
    console.log('licence signing key loaded from ' + how);
    return k;
  } catch (e) { console.error('\nFATAL: licence signing key is unreadable: ' + e.message + '\n'); process.exit(1); }
}
const SIGNING_KEY = loadSigningKey();

// Mint a signed grant. The payload binds the licence to ONE machine and ONE moment; the client verifies the
// signature over the encoded token, so no field inside it can be edited after the fact.
function signGrant({ license, hwid, tier, expires, nonce }) {
  const payload = { v: 1, key: String(license).toUpperCase(), hwid: String(hwid || ''), tier: tier || 'standard', iat: Date.now(), exp: Number(expires) || 0, nonce: String(nonce || '') };
  const token = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.sign(null, Buffer.from(token, 'utf8'), SIGNING_KEY).toString('base64');
  return { token, sig };
}

const app = express();
app.use(express.json({ limit: '64kb' }));
app.set('trust proxy', 1); // we sit behind an HTTPS reverse proxy; trust X-Forwarded-* for req.ip

// Dependency-free fixed-window rate limiter (M3-04). Per-IP; throttles brute-force key guessing and
// DoS without pulling in express-rate-limit. Entries self-expire; the map is pruned periodically.
function rateLimiter({ windowMs, max, name }) {
  const hits = new Map();
  setInterval(() => { const now = Date.now(); for (const [ip, e] of hits) if (now - e.start >= windowMs) hits.delete(ip); }, windowMs).unref();
  return (req, res, next) => {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    let e = hits.get(ip);
    if (!e || now - e.start >= windowMs) { e = { start: now, count: 0 }; hits.set(ip, e); }
    if (++e.count > max) return res.status(429).json({ valid: false, message: 'Too many requests — slow down.' });
    next();
  };
}

// Constant-time secret compare (2026-08-05 vps audit F2): the Bearer token guards the FULL keystore (/api/keys) and the
// click data (/api/clicks); a short-circuiting `!==` leaks a prefix-length timing signal. timingSafeEqual on equal-length
// buffers removes it (the length guard leaks only the length, not the secret).
function safeEq(a, b) {
  const ab = Buffer.from(String(a == null ? '' : a)), bb = Buffer.from(String(b == null ? '' : b));
  if (ab.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ab, bb); } catch { return false; }
}
// Admin auth — prefer Authorization: Bearer <ADMIN_TOKEN> (M3-04); the ?admin= query param is a
// DEPRECATED fallback (it leaks into proxy/access logs). 403 when ADMIN_TOKEN is unset.
function adminAuth(req, res, next) {
  const token = process.env.ADMIN_TOKEN;
  if (!token) return res.status(403).json({ error: 'admin disabled — set ADMIN_TOKEN' });
  const hdr = req.get('authorization') || '';
  // Header-only (Bearer) — the ?admin= query fallback was removed: query strings leak into Nginx/Cloudflare
  // access logs, exposing ADMIN_TOKEN. Send `Authorization: Bearer <token>`.
  const provided = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  if (!safeEq(provided, token)) return res.status(403).json({ error: 'forbidden' });
  next();
}

// Seed the owner key from an env var so the secret never lives in Git. Added once if missing.
try {
  const ownerKey = String(process.env.OWNER_KEY || '').trim().toUpperCase();
  if (ownerKey) {
    const db = ks.load();
    if (!db[ownerKey]) {
      db[ownerKey] = { hwid: null, revoked: false, expires: null, tier: 'owner', note: 'owner', createdAt: 0 };
      ks.save(db); ks.audit('create', ownerKey, 'owner (seeded from env)');
      console.log('Seeded owner key from env');
    }
  }
} catch (e) { console.error('owner seed:', e.message); }

app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

// ── CLICK TRACKING (per-group / per-account) ─────────────────────────────────────────────────────────────────────────
// The desktop app posts links like  https://<this-host>/r?g=<groupId>&a=<account>&p=<postId>  into Facebook groups.
// A real click here is LOGGED (to /data/clicks.jsonl, persistent) then 302-redirected to CLICK_DEST — the ONE shared
// offer URL, configured server-side so /r can never be abused as an open redirect. The app reads /api/clicks to show
// per-group AND per-account totals. Isolated from licence validation: /r is public + wrapped so it can never throw, and
// /api/clicks uses its OWN token (CLICK_TOKEN, least-privilege — NOT the admin token).
const clicks = require('./clicks');
const { decodeClick } = require('./clickToken'); // authentic clean links: /r/<slug>/<token> — decode the opaque analytics token
const blogMap = require('./blogMap'); // MULTI-BLOG (2026-08-08): map an incoming tracking host (go.<blog>) → that blog's destination origin
const CLICK_DEST = String(process.env.CLICK_DEST || '').trim();
const CLICK_TOKEN = String(process.env.CLICK_TOKEN || '').trim();
// Per-post destinations: the app posts the REAL article URL in `u`, so a click lands on the right page (not one homepage).
// To keep /r from being an open redirect (a phishing vector), `u` is honoured ONLY when its host is allow-listed: the host
// of CLICK_DEST, plus any extra hosts in CLICK_HOSTS (comma-separated). Anything else falls back to CLICK_DEST.
let CLICK_DEST_HOST = ''; try { CLICK_DEST_HOST = new URL(CLICK_DEST).host.toLowerCase(); } catch {}
let CLICK_DEST_ORIGIN = ''; try { CLICK_DEST_ORIGIN = new URL(CLICK_DEST).origin; } catch {} // scheme+host of the blog — the FIXED base the /r/<slug>/<token> route rebuilds destinations against (so a click can never leave it)
const CLICK_HOSTS = String(process.env.CLICK_HOSTS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const clickHostAllowed = (h) => { h = String(h || '').toLowerCase(); return (!!CLICK_DEST_HOST && h === CLICK_DEST_HOST) || CLICK_HOSTS.includes(h); };
// Social/link-preview crawlers pre-fetch every posted link (Facebook fetches it once to build the preview card). Those are
// NOT human clicks — filter them out of the count so the preview fetch doesn't inflate every group by one. Real users in
// Facebook's in-app browser send FBAN/FBAV (NOT matched here), so their clicks are still counted.
const CLICK_BOT_RE = /bot|crawl|spider|facebookexternalhit|facebot|linkpreview|preview|slurp|bingpreview|whatsapp|telegram|discord|headless|monitor|pingdom|uptimerobot|curl|wget|python-requests|axios|node-fetch/i;
app.get('/r', rateLimiter({ windowMs: 60000, max: 600, name: 'r' }), (req, res) => { // round-4: /r had NO limiter (every other route does). Generous (600/min/IP ≈ 10/s — well above any legit shared-IP click rate) so it only trips an egregious single-IP flood; the clicks.js size cap is the hard disk-exhaustion backstop for a DISTRIBUTED flood.
  try {
    // Prefer the per-post article URL in `u` (host-allow-listed); else the shared CLICK_DEST.
    let target = CLICK_DEST, uPath = '';
    const u = String(req.query.u || '');
    if (u) { try { const x = new URL(u); uPath = x.pathname; if (clickHostAllowed(x.host)) target = x.href; } catch {} } // send the WHATWG-normalized href (not the raw u) so a tab/newline differential-parse can't smuggle a Location header (2026-08-05 vps audit F7; matches the /r/* clean route's d.href)
    if (!target) return res.status(503).type('text').send('Click tracking is not configured (set CLICK_DEST).');
    const ua = String(req.get('user-agent') || '');
    if (!CLICK_BOT_RE.test(ua)) {
      clicks.logClick({ ts: new Date().toISOString(), g: String(req.query.g || '').slice(0, 80), a: String(req.query.a || '').slice(0, 80), p: String(req.query.p || '').slice(0, 80), c: String(req.query.c || '').slice(0, 80), u: uPath.slice(0, 300), ip: req.ip, ua: ua.slice(0, 200) });
    }
    return res.redirect(302, target);
  } catch (e) { try { return CLICK_DEST ? res.redirect(302, CLICK_DEST) : res.status(500).end(); } catch { return; } }
});
// AUTHENTIC clean links (2026-08-01):  /r/<slug>/<token>  — the app publishes host/r/<real-article-slug>/<opaque-token>
// instead of host/r?g=..&u=<realurl>. The visible slug reads like a genuine article; the analytics {g,a,p,c} ride in the
// opaque token; the destination is NOT in the link — it is rebuilt HERE as CLICK_DEST_ORIGIN + '/' + slug (+ carried
// query/fragment). Resolving the slug as a RELATIVE path against our own origin + re-checking the host allow-list makes
// an open redirect impossible even though the slug is attacker-shaped. Same bot filter + logging shape as /r above.
app.get('/r/*', rateLimiter({ windowMs: 60000, max: 600, name: 'r-clean' }), (req, res) => {
  try {
    // MULTI-BLOG: the destination origin is the blog THIS tracking host fronts (go.<blog> → https://<blog>), from blogMap.
    // Fall back to the legacy single CLICK_DEST_ORIGIN so links already live on the VPS's own host keep resolving.
    const blogOrigin = blogMap.resolve(req.hostname) || CLICK_DEST_ORIGIN;
    if (!blogOrigin) return CLICK_DEST ? res.redirect(302, CLICK_DEST) : res.status(503).type('text').send('Click tracking is not configured (set CLICK_BLOGS / blogs.json or CLICK_DEST).');
    let blogHost = ''; try { blogHost = new URL(blogOrigin).host.toLowerCase(); } catch {}
    const rest = String(req.params[0] || '');
    const segs = rest.split('/').filter(Boolean);
    const token = segs.pop() || '';
    const slug = segs.join('/');
    const payload = decodeClick(token);
    if (!payload) return res.redirect(302, CLICK_DEST); // not one of our tokens (bare probe, favicon, typo) → the shared offer, no log
    // Rebuild the destination against the RESOLVED blog origin. A relative resolve can't override the authority; re-verify the
    // rebuilt host is the blog's OWN host (per-blog) or globally allow-listed (legacy links / CLICK_HOSTS). Else → CLICK_DEST
    // (never an open redirect, regardless of what the attacker-shaped slug says).
    let dest = CLICK_DEST, destPath = '';
    try { const d = new URL(slug + (payload.q || '') + (payload.f || ''), blogOrigin + '/'); const dh = d.host.toLowerCase(); if (dh === blogHost || clickHostAllowed(dh)) { dest = d.href; destPath = d.pathname; } } catch {}
    const ua = String(req.get('user-agent') || '');
    if (!CLICK_BOT_RE.test(ua)) {
      clicks.logClick({ ts: new Date().toISOString(), g: String(payload.g || '').slice(0, 80), a: String(payload.a || '').slice(0, 80), p: String(payload.p || '').slice(0, 80), c: String(payload.c || '').slice(0, 80), u: destPath.slice(0, 300), b: blogHost.slice(0, 120), ip: req.ip, ua: ua.slice(0, 200) });
    }
    return res.redirect(302, dest);
  } catch (e) { try { return CLICK_DEST ? res.redirect(302, CLICK_DEST) : res.status(500).end(); } catch { return; } }
});
// TRACKING PIXEL (2026-08-08, multi-blog-via-the-blog-itself): the app posts the REAL article link with a ?ref=<token> tag,
// so the link stays a genuine article on the blog's own domain (Facebook shows the real card, no redirect). Counting is done
// BY THE BLOG: the za-click-pixel mu-plugin, when a real visitor opens a ?ref= link, loads this 1×1 pixel with the token (t)
// and the blog host (b). We decode the analytics {g,a,p,c}, log the click, and return a transparent GIF. Bot UAs are filtered
// (the plugin already skips them server-side; this is a second guard). no-store so each open re-fetches (a cached pixel would
// undercount). Isolated + wrapped so it can never throw. Same clicks log + /api/clicks aggregation as /r.
const PX_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'); // 1×1 transparent GIF
app.get('/px', rateLimiter({ windowMs: 60000, max: 1200, name: 'px' }), (req, res) => {
  try {
    const payload = decodeClick(String(req.query.t || ''));
    const ua = String(req.get('user-agent') || '');
    if (payload && !CLICK_BOT_RE.test(ua)) {
      const b = String(req.query.b || '').toLowerCase().replace(/[^a-z0-9.\-]/g, '').slice(0, 120); // blog host, set by the plugin
      clicks.logClick({ ts: new Date().toISOString(), g: String(payload.g || '').slice(0, 80), a: String(payload.a || '').slice(0, 80), p: String(payload.p || '').slice(0, 80), c: String(payload.c || '').slice(0, 80), u: '', b, ip: req.ip, ua: ua.slice(0, 200) });
    }
  } catch {}
  try { res.set('Content-Type', 'image/gif'); res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0'); res.set('Pragma', 'no-cache'); return res.status(200).end(PX_GIF); }
  catch { try { return res.status(204).end(); } catch { return; } }
});
// Aggregated click counts for the desktop app. Bearer <CLICK_TOKEN> ONLY (no ?token= query fallback — query strings leak
// into proxy access logs, per the same reasoning that removed ?admin= from the admin route).
app.get('/api/clicks', rateLimiter({ windowMs: 60000, max: 60, name: 'clicks' }), (req, res) => {
  if (!CLICK_TOKEN) return res.status(403).json({ error: 'clicks disabled — set CLICK_TOKEN' });
  const hdr = req.get('authorization') || '';
  const provided = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  if (!safeEq(provided, CLICK_TOKEN)) return res.status(403).json({ error: 'forbidden' });
  try { res.json(clicks.aggregate(String(req.query.since || '').trim() || undefined)); } catch (e) { res.status(500).json({ error: String((e && e.message) || e) }); }
});

// SERVER-SIDE pageview log (2026-08-12): the za-click-log mu-plugin fire-and-forgets a POST here on a Facebook-referred
// article view. Unlike the /px client pixel, there is NO on-page beacon and NO tracking token in the URL — the count
// happens on the WordPress SERVER, invisible to the ad tags, so it CANNOT affect AdSense/AdX RPM (the whole reason /px
// collapsed RPM). Same clicks store, aggregated per (blog, article) as `byArticle`. Per-post/group is recovered app-side
// by time-correlating with the poster's delivery log (the clean links carry no token). Bot-filtered server-side like /px.
app.post('/log', rateLimiter({ windowMs: 60000, max: 6000, name: 'log' }), (req, res) => {
  try {
    const b = String((req.body && req.body.b) || '').toLowerCase().replace(/[^a-z0-9.\-]/g, '').slice(0, 120);
    const pth = String((req.body && req.body.p) || '').slice(0, 300);
    const f = String((req.body && req.body.f) || '').slice(0, 120);
    const ua = String(req.get('user-agent') || '');
    if (b && pth && !CLICK_BOT_RE.test(ua)) { clicks.logClick({ ts: new Date().toISOString(), b, path: pth, f, ip: req.ip }); }
  } catch {}
  try { return res.status(204).end(); } catch { return; }
});

// Raw server-side pageviews for the desktop app's time-correlation attribution (Bearer <CLICK_TOKEN>, same as /api/clicks).
// The app fetches these and joins them with its own delivery log to recover per-group/account clicks — no on-page token.
app.get('/api/pageviews', rateLimiter({ windowMs: 60000, max: 60, name: 'pageviews' }), (req, res) => {
  if (!CLICK_TOKEN) return res.status(403).json({ error: 'clicks disabled — set CLICK_TOKEN' });
  const hdr = req.get('authorization') || '';
  const provided = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  if (!safeEq(provided, CLICK_TOKEN)) return res.status(403).json({ error: 'forbidden' });
  try { res.json({ pageviews: clicks.pageviews(String(req.query.since || '').trim() || undefined) }); } catch (e) { res.status(500).json({ error: String((e && e.message) || e) }); }
});

// DEBOUNCE the lastSeen persist (2026-08-05 vps audit F1): a re-validation only needs to REFRESH lastSeen, but writing the
// whole (scryptSync-encrypted) store on EVERY launch is what a flood weaponizes. Persist at most hourly per license; the
// in-memory value (in the mtime-cached store) is always current. Not persisted across a restart — it rebuilds on the first
// post-restart validate. license → last-persisted-ts.
const _lastSeenSaved = new Map();
// Validate + bind a license to one machine (HWID). First activation binds; later launches must come
// from the same machine. Revoked/expired keys are rejected. Returns the tier + limits the client
// enforces (per-seat model).
app.post('/api/validate', rateLimiter({ windowMs: 60000, max: 30, name: 'validate' }), (req, res) => {
  const license = String((req.body && req.body.license) || '').trim().toUpperCase();
  const hwid = String((req.body && req.body.hwid) || '').trim();
  const ver = String((req.body && req.body.ver) || '').replace(/[^0-9.a-z-]/gi, '').slice(0, 24); // client app version — telemetry + the version gate. STRIP to version chars (adversary #2): ver is rendered RAW in list-keys.js, so control/ANSI chars could hide a CLONE flag in the operator's terminal. ('' from an older client → grandfathered)
  const acc = Math.max(0, Math.min(99999, Number((req.body && req.body.acc)) || 0)); // reported account count — telemetry only
  const grp = Math.max(0, Math.min(99999, Number((req.body && req.body.grp)) || 0)); // reported group count — telemetry only
  // round-4: reject an empty/short hwid up front. An empty hwid binds FALSY (rec.hwid='' → never actually locks, so any
  // machine re-binds it) AND skips the "already active on another device" check below → a known key can be squatted/pre-bound
  // by anyone who learns the string, locking out the real buyer. The legit client never POSTs a null/short id (a real
  // machine id is 32+ chars); this only rejects malformed/malicious requests.
  if (!hwid || hwid.length < 8) return res.json({ valid: false, message: 'Missing or invalid device id' });
  let db;
  try { db = ks.load(); } catch (e) { console.error('keys load:', e.message); return res.status(503).json({ valid: false, message: 'Server key store unavailable' }); }
  const rec = Object.prototype.hasOwnProperty.call(db, license) ? db[license] : undefined; // OWN-property only (adversary note): don't let db['__proto__'] etc. resolve to an inherited object; belt-and-suspenders beyond the toUpperCase that already misses __proto__
  if (!rec) return res.json({ valid: false, message: 'Invalid license key' });
  if (rec.revoked) return res.json({ valid: false, revoked: true, message: 'This license has been revoked' });
  if (rec.expires && Date.now() > rec.expires) return res.json({ valid: false, message: 'License expired' });
  // ★2026-08-15 SUSPEND (reversible, operator-set via suspend.js after reviewing a clone flag): honor a suspended seat.
  // Fail-CLOSED, but deliberate → no false-positive lockout; distinct from revoke (permanent, wipes the client cache).
  if (rec.suspended) return res.json({ valid: false, suspended: true, message: rec.suspendMessage || 'License suspended — contact support.' });
  // ★2026-08-15 VERSION GATE: reject a client older than the required minimum (per-key rec.minVersion OR global env
  // MIN_CLIENT_VERSION). FORCES HONEST clients to update + retires old versions — NOT anti-piracy (adversary #3: a cracked
  // client self-reports ver='' → grandfathered, or a fake-high ver; for theft rely on revoke/suspend + the asar-integrity
  // seal). FAIL-OPEN for the no-version / unset-min cases. ⚠ OPERATOR FOOTGUN (adversary #4): set the minimum ≤ the version
  // you have ACTUALLY shipped — a value ABOVE it locks out the WHOLE up-to-date fleet (every seat reports a real ver < min →
  // valid:false, no offline grace). Recoverable in ≤1h by fixing the env (the fleet re-validates hourly); a boot warning fires.
  const _minVer = String(rec.minVersion || process.env.MIN_CLIENT_VERSION || '').trim();
  if (_minVer && ver && ks.semverLt(ver, _minVer)) return res.json({ valid: false, outdated: true, minVersion: _minVer, message: 'Please update to version ' + _minVer + ' or later to continue.' });
  // Echo the client's nonce inside the signed token so this response cannot be replayed to activate a second
  // install. Capped — it is opaque to us and only ever compared for equality.
  const nonce = String((req.body && req.body.nonce) || '').trim().slice(0, 64);
  const grant = () => ({
    valid: true, message: 'OK', tier: rec.tier || 'standard', maxAccounts: rec.maxAccounts, maxGroups: rec.maxGroups, expires: rec.expires || 0,
    // Sign against the BOUND machine, not merely the requesting one, so the token can never attest to a device the
    // key store did not actually bind.
    ...signGrant({ license, hwid: rec.hwid || hwid, tier: rec.tier, expires: rec.expires, nonce }),
  });
  if (rec.hwid == null) { rec.hwid = hwid; rec.activatedAt = Date.now(); ks.save(db); ks.audit('bind', license, 'hwid=' + hwid.slice(0, 8)); return res.json({ ...grant(), message: 'Activated' }); } // == null (not !rec.hwid): a genuinely UNBOUND record is null (gen-key / reset-hwid); a hand-edited/legacy '' hwid must NOT be treated as bindable-by-anyone — it falls to the strict compare below and is rejected as "already active on another device" (fail closed). New binds always write a ≥8-char id (front-door gate), so real records are never '' → no legit impact.
  if (hwid && rec.hwid !== hwid) return res.json({ valid: false, message: 'License is already active on another device' });
  rec.lastSeen = Date.now(); // always current in the in-memory (cached) store
  // ★2026-08-15 telemetry — PER-BRAND so ONE client running all 4 brand-apps (same key + hwid, separate userData each,
  // reporting on their own cycles) shows a COMBINED total instead of the apps overwriting each other's counts. `brand` is
  // client-controlled and becomes an object key → sanitize HARD: strip to [a-z0-9-] (removes the underscores in __proto__),
  // cap length, and reject the prototype-pollution names. Prune brands not seen in 14 days so a client that stopped running
  // one app doesn't inflate the total forever. Bounded (a handful of brands per key). list-keys.js sums rec.apps.
  if (ver) rec.lastVersion = ver; // keep the most-recent version at top level (backward-compat + display)
  const _sb = ks.recordAppTelemetry(rec, brand, { ver, acc, grp }, rec.lastSeen); // per-brand aggregate → combined per-client total (list-keys.js sums rec.apps)
  if (!_sb) { if (acc) rec.lastAccounts = acc; if (grp) rec.lastGroups = grp; } // no brand (older client) → flat single-app telemetry
  const _lsPrev = _lastSeenSaved.get(license) || 0;
  let _persisted = false;
  if (rec.lastSeen - _lsPrev > 3600000) { _lastSeenSaved.set(license, rec.lastSeen); ks.save(db); _persisted = true; } // persist at most hourly per license (mtime-cached load + this debounce = a re-validation flood costs ~0 scrypt/disk)
  // ★RANK-2 (2026-08-15): flag a probable MachineGuid CLONE by IP fan-out — the one clone vector the client hwid lock can't
  // catch (every clone presents the same bound hwid, so the `rec.hwid !== hwid` check above passes for all copies). FLAG
  // ONLY, never deny: a legit roaming/mobile/VPN seat also spans IPs, so the operator reviews flagged keys (visible in
  // /api/keys + key-audit.log) and revokes a confirmed share. req.ip is the real client IP (trust proxy: 1).
  try {
    const ip = String(req.ip || '').slice(0, 45);
    const { distinct } = ks.recordValidationIp(rec, ip, rec.lastSeen, {}); // ipLog mutates the in-memory (cache-by-ref) record → clone detection stays current WITHOUT a per-request encrypted save
    const FLAG_IPS = 6; // one honest seat is ~1 IP; ≥6 distinct in 24h is a strong clone/share signal (tunable)
    if (distinct >= FLAG_IPS) {
      const _wasFlagged = rec.flagged && rec.flagged.reason === 'multi-ip';
      rec.flagged = { reason: 'multi-ip', ips: distinct, at: rec.lastSeen }; // refresh the count in-memory (cheap); the hourly save flushes it durably
      // ★2026-08-15 DoS fix (adversary #1): persist + audit ONCE, only on the FIRST raise — NEVER per new IP. Every encrypted
      // ks.save() runs scryptSync (CPU-hard, blocks the event loop), so saving per-IP let a bound key POSTing from >50
      // rotating IPs pin the server. The flag count still refreshes in-memory each request; the hourly debounce flushes it.
      if (!_wasFlagged) { try { ks.audit('flag', license, 'multi-ip fan-out=' + distinct + ' in 24h (possible MachineGuid clone) — review + suspend/revoke if shared'); } catch {} _lastSeenSaved.set(license, rec.lastSeen); ks.save(db); }
    }
  } catch (e) { try { console.error('ip-track:', e.message); } catch {} }
  return res.json(grant());
});

// Admin view of all keys.
app.get('/api/keys', rateLimiter({ windowMs: 60000, max: 20, name: 'keys' }), adminAuth, (_req, res) => {
  try { res.json(ks.load()); } catch (e) { res.status(503).json({ error: 'key store unavailable: ' + e.message }); }
});

const PORT = process.env.PORT || 3509;
if (!ks.isEncryptedAtRest()) console.warn('⚠️  KEYS_ENCRYPTION_KEY is not set — the key store is stored in PLAINTEXT. Set it to encrypt keys.json at rest (see DEPLOY-COOLIFY.md).');
if (process.env.MIN_CLIENT_VERSION) console.warn('⚠️  VERSION GATE ACTIVE: MIN_CLIENT_VERSION=' + process.env.MIN_CLIENT_VERSION + ' — EVERY client reporting a lower version is denied at its next check (no offline grace). Ensure this is ≤ the version you have actually shipped, or the whole fleet locks out.');
app.listen(PORT, '0.0.0.0', () => console.log('Za Post license server listening on :' + PORT + (ks.isEncryptedAtRest() ? ' (key store encrypted)' : '')));
