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
  let k;
  try { k = crypto.createPrivateKey(pem); }
  catch (e) { console.error('\nFATAL: licence signing key is unreadable: ' + e.message + '\n'); process.exit(1); }
  // ★2026-08-16: assert this is the ONE key the shipped clients pin (LICENSE_PUBKEY). createPrivateKey only proves the value
  // is a readable Ed25519 key — NOT that it is the RIGHT one. A rotated / mis-pasted key boots green and mints grants signed
  // by the wrong key; every already-shipped client rejects them as unsigned → the whole paying fleet drifts into offline-grace
  // lockout within 7 days, with ZERO server-side error. Fail LOUD on mismatch (like the missing-key guard above) so a bad
  // rotation FAILS the deploy + rolls back instead of silently bricking. For a DELIBERATE key rotation, ship a client build
  // carrying the new public half FIRST, then set the LICENSE_PUBKEY env here to match.
  const EXPECT_PUB = String(process.env.LICENSE_PUBKEY || '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAQQ9h0QKdPXyQrD8Nr/49YbxRufo/vo8/Jx0kymUWqm8=\n-----END PUBLIC KEY-----').replace(/\r/g, '').trim();
  try {
    const gotPub = crypto.createPublicKey(k).export({ type: 'spki', format: 'pem' }).replace(/\r/g, '').trim();
    if (EXPECT_PUB && gotPub !== EXPECT_PUB) {
      console.error('\nFATAL: the licence signing key does NOT match the public key compiled into shipped clients.');
      console.error('  Grants signed by this key are REJECTED by every client as unsigned → fleet lockout within the 7-day grace.');
      console.error('  Almost always a mis-paste or an un-coordinated key rotation. Restore the correct LICENSE_SIGNING_KEY,');
      console.error('  or — for a DELIBERATE rotation — ship a client with the new LICENSE_PUBKEY first, then set the LICENSE_PUBKEY env here.\n');
      process.exit(1);
    }
  } catch (e) { console.error('WARNING: could not derive the signing key public half to verify it: ' + (e && e.message)); }
  console.log('licence signing key loaded from ' + how + ' (public half matches the shipped client)');
  return k;
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

// ★2026-08-16 (BRICK): guard against an UNMOUNTED persistent volume. Persistence depends 100% on Coolify mounting a volume
// at KEYS_PATH's dir (/data). If that mount is missing or the path is typo'd, /data is an EPHEMERAL container-layer dir: the
// store loads empty, we seed owner-only + accept customer activations, and the FIRST redeploy wipes every key + HWID bind —
// unrecoverable (reset-keys backups live on the same lost volume; the owner's OWN app silently re-seeds + re-binds, so a
// smoke test still passes while the whole fleet is down). Detect it: an EMPTY store whose dir shares the container-ROOT
// device (or whose dir does not even exist) is a volume that isn't mounted → refuse to boot (loud → Coolify rolls back),
// unless this is a deliberate first install (ALLOW_EMPTY_KEYSTORE=1). A real mounted volume has its OWN st_dev → never trips.
// Linux-container-only: a local dev run (Windows, or without KEYS_PATH) is exempt.
try {
  if (process.platform !== 'win32' && String(process.env.KEYS_PATH || '').trim() && !String(process.env.ALLOW_EMPTY_KEYSTORE || '').trim()) {
    let _empty = false; try { _empty = Object.keys(ks.load()).length === 0; } catch {}
    if (_empty) {
      const _dir = path.dirname(String(process.env.KEYS_PATH));
      let _unmounted = false;
      try { _unmounted = fs.statSync(_dir).dev === fs.statSync('/').dev; }
      catch (e) { if (e && e.code === 'ENOENT') _unmounted = true; } // the volume dir does not even exist → definitely not mounted
      if (_unmounted) {
        console.error('\nFATAL: key store dir ' + JSON.stringify(_dir) + ' is EMPTY and on the CONTAINER ROOT filesystem, not a mounted persistent volume.');
        console.error('  Every activation would be LOST on the next redeploy (customer keys + HWID binds — unrecoverable).');
        console.error('  Fix: in Coolify, add persistent storage mounted at ' + JSON.stringify(_dir) + ', Save, Redeploy.');
        console.error('  If this really is a fresh first install on a correctly-mounted volume, set ALLOW_EMPTY_KEYSTORE=1 for ONE deploy, then remove it.\n');
        process.exit(1);
      }
    }
  }
} catch {}

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

// ★2026-08-16: readiness, not just liveness. The Docker HEALTHCHECK hits this; if it never touched the key store, a
// keystore-UNREADABLE state (KEYS_ENCRYPTION_KEY rotated/removed, or a CLI re-encrypted the store with a divergent key →
// ks.load() throws → every /api/validate 503s) would stay GREEN, so Coolify keeps the broken container live + never rolls
// back, and the whole fleet drifts into grace lockout while the dashboard shows healthy. Probe ks.load() so a store the
// running key can't decrypt FAILS the deploy → rollback. ENOENT (genuine first boot) returns {} — not a throw → stays healthy.
app.get('/health', (_req, res) => { try { ks.load(); return res.status(200).json({ ok: true }); } catch (e) { try { console.error('health: key store unreadable:', e && e.message); } catch {} return res.status(503).json({ ok: false, error: 'key store unavailable' }); } });

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
// ★RANK-2b (2026-08-16): concurrency / second-machine thresholds (see keystore.recordDeviceConcurrency). FLAG-ONLY by default — a
// flag is cosmetic (list-keys ⚠️), NEVER a denial, so it cannot brick a paying seat. FLAG_HWIDS: the bound machine AND ≥1 other
// distinct hwid both heartbeating in the window ⇒ a real second box. RATE_HITS: one hwid validating far above a single seat's
// ceiling (4 brand-apps × hourly ≈ 8 per 2h; generous restarts push higher) ⇒ many same-hwid clones behind one NAT — muddy, so
// it sits well above any honest 4-brand rate. AUTO-SUSPEND is OFF unless CLONE_AUTOSUSPEND=1, gated on a HIGHER distinct-hwid bar,
// and is REVERSIBLE (suspend.js --lift). HONEST: /api/validate is unauthenticated (key+hwid), so anyone holding the KEY string can
// forge extra hwids to trip a flag (or, with auto-suspend on, a suspend) — that is exactly why auto-suspend defaults OFF and the
// operator reviews the flag before acting.
const CONC_WINDOW_MS = 2 * 3600 * 1000;
const FLAG_HWIDS = 2;                                              // bound machine + ≥1 other distinct hwid active in the window
const RATE_HITS = Number(process.env.CLONE_RATE_HITS) || 40;       // same-hwid validate count in the window that implies multiple concurrent instances (tunable; keep >> a 4-brand seat)
const SUSPEND_HWIDS = Number(process.env.CLONE_SUSPEND_HWIDS) || 3; // auto-suspend bar (only when CLONE_AUTOSUSPEND=1)
const CLONE_AUTOSUSPEND = String(process.env.CLONE_AUTOSUSPEND || '').trim() === '1';
// ★LEAK-TRACE (2026-08-17): auto-suspend a key whose build watermark (seat) belongs to a DIFFERENT customer than it first
// activated with — a leaked build in the wild. OFF by default (flag-only, operator reviews); set LEAK_AUTOSUSPEND=1 to auto-act.
const LEAK_AUTOSUSPEND = String(process.env.LEAK_AUTOSUSPEND || '').trim() === '1';
// seatClient (the CUSTOMER part of a build seat — strips the -app<n> brand suffix so a legit 4-brand seat never mismatches)
// lives in keystore.js (ks.seatClient), unit-tested alongside the other pure helpers.
// Validate + bind a license to one machine (HWID). First activation binds; later launches must come
// from the same machine. Revoked/expired keys are rejected. Returns the tier + limits the client
// enforces (per-seat model).
app.post('/api/validate', rateLimiter({ windowMs: 60000, max: 30, name: 'validate' }), (req, res) => {
  // ★#8 CAS INVARIANT (2026-08-17): the ks.save(db, { cas: true }) calls below rely on load→save staying SYNCHRONOUS — do
  // NOT introduce an `await` between ks.load() and any ks.save() in this handler. An await would let another request
  // interleave and break the "module-cached identity == the db this save is derived from" invariant the CAS depends on.
  const license = String((req.body && req.body.license) || '').trim().toUpperCase();
  const hwid = String((req.body && req.body.hwid) || '').replace(/[^\x20-\x7E]/g, '').trim().slice(0, 128); // ★2026-08-16: strip non-printable/ANSI + cap length — mirror the `ver` sanitize below (rec.hwid renders RAW in list-keys.js, so a control/ESC-injected hwid could CONCEAL a ⚠️ clone flag in the operator's terminal). node-machine-id's real id is sha256-hex/GUID/hostname — all printable ASCII — so a legit seat is untouched (no device-lock regression); an all-ANSI hwid strips to '' and is rejected by the length gate below.
  const ver = String((req.body && req.body.ver) || '').replace(/[^0-9.a-z-]/gi, '').slice(0, 24); // client app version — telemetry + the version gate. STRIP to version chars (adversary #2): ver is rendered RAW in list-keys.js, so control/ANSI chars could hide a CLONE flag in the operator's terminal. ('' from an older client → grandfathered)
  const acc = Math.max(0, Math.min(99999, Number((req.body && req.body.acc)) || 0)); // reported account count — telemetry only
  const grp = Math.max(0, Math.min(99999, Number((req.body && req.body.grp)) || 0)); // reported group count — telemetry only
  const brand = String((req.body && req.body.brand) || ''); // reported brand-app name — telemetry only; recordAppTelemetry sanitizes it HARD (strips to [a-z0-9-], caps length, rejects proto names). ★2026-08-16: this was UNDECLARED at line ~348 → ReferenceError on every re-validation → 500 → offline-grace lockout. Declared here + the tail is now try-wrapped so telemetry can never break the grant.
  const seat = String((req.body && req.body.seat) || '').replace(/[^A-Za-z0-9._-]/g, '').slice(0, 64); // ★LEAK-TRACE: per-build customer watermark — telemetry + leak detection. STRIP to safe chars (renders RAW in list-keys.js, same ANSI-hiding concern as ver/hwid). '' from an older/cracked client → grandfathered (never a denial).
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
    // ★NOTICE CHANNEL (2026-08-17): rec.message (operator-set per key) rides the grant → the client surfaces it in its
    // license status. A soft, non-blocking way to reach one client ("your trial ends in 3 days", "payment overdue") without
    // suspending — for a hard stop use suspend.js/revoke.js. Defaults to 'OK' so behaviour is unchanged unless a message is set.
    valid: true, message: rec.message || 'OK', tier: rec.tier || 'standard', maxAccounts: rec.maxAccounts, maxGroups: rec.maxGroups, expires: rec.expires || 0,
    // Sign against the BOUND machine, not merely the requesting one, so the token can never attest to a device the
    // key store did not actually bind.
    ...signGrant({ license, hwid: rec.hwid || hwid, tier: rec.tier, expires: rec.expires, nonce }),
  });
  if (rec.hwid == null) { rec.hwid = hwid; rec.activatedAt = Date.now(); rec.hwidLog = [{ hwid, ts: Date.now(), n: 1 }]; /* ★RANK-2b: seed the concurrency log on a fresh bind / reset-hwid rebind so a stale pre-reset hwid can't instantly read as a second machine */ try { if (ver) rec.lastVersion = ver; if (!ks.recordAppTelemetry(rec, brand, { ver, acc, grp }, Date.now())) { if (acc) rec.lastAccounts = acc; if (grp) rec.lastGroups = grp; } if (seat) { rec.lastSeat = seat; const _sc = ks.seatClient(seat); if (_sc) rec.seatClient = _sc; } } catch {} /* ★2026-08-16 F2: record telemetry on FIRST activation too, else a fresh key shows no ver/acc/grp until its first hourly re-validation. ★LEAK-TRACE: seed the seat baseline here so a leaked build is caught on its FIRST re-check, not one cycle late */ try { ks.save(db, { cas: true }); } catch (e) { if (!(e && e.code === 'KEYSTORE_CONFLICT')) throw e; } /* ★#8 CAS: an admin write (revoke/reset) won the race — skip the bind; it self-heals on the next launch after load() re-reads disk */ ks.audit('bind', license, 'hwid=' + hwid.slice(0, 8)); return res.json({ ...grant(), message: 'Activated' }); } // == null (not !rec.hwid): a genuinely UNBOUND record is null (gen-key / reset-hwid); a hand-edited/legacy '' hwid must NOT be treated as bindable-by-anyone — it falls to the strict compare below and is rejected as "already active on another device" (fail closed). New binds always write a ≥8-char id (front-door gate), so real records are never '' → no legit impact.
  if (hwid && rec.hwid !== hwid) {
    // ★RANK-2b (2026-08-16): a DIFFERENT hwid on a BOUND key is either the honest owner on a new PC (rare; handled by reset-hwid)
    // or the key being run on a SECOND MACHINE. We STILL DENY (the bind-lock holds) but RECORD the attempt so a real second box —
    // the bound machine AND this one both heartbeating in the window — surfaces as a clone FLAG (never a denial here). Wrapped so
    // concurrency tracking can NEVER change the deny; lastSeen is NOT touched (this requester is not the seat).
    try {
      const { distinctHwids } = ks.recordDeviceConcurrency(rec, hwid, Date.now(), { windowMs: CONC_WINDOW_MS });
      if (distinctHwids >= FLAG_HWIDS) {
        const _wasFlagged = rec.flagged && rec.flagged.reason === 'multi-hwid';
        rec.flagged = { reason: 'multi-hwid', hwids: distinctHwids, at: Date.now() }; // refresh in-memory (cheap); the save below flushes it durably
        if (CLONE_AUTOSUSPEND && distinctHwids >= SUSPEND_HWIDS && !rec.suspended) {
          rec.suspended = true; rec.suspendMessage = 'License suspended — key active on ' + distinctHwids + ' machines (auto). Contact support.';
          try { ks.audit('suspend', license, 'AUTO multi-hwid=' + distinctHwids + ' (CLONE_AUTOSUSPEND) — REVERSIBLE with suspend.js --lift'); } catch {}
          _lastSeenSaved.set(license, Date.now()); ks.save(db, { cas: true });
        } else if (!_wasFlagged) { // persist + audit ONCE on the FIRST raise (mirror the multi-ip flag — never a scryptSync save per request)
          try { ks.audit('flag', license, 'multi-hwid=' + distinctHwids + ' in ' + (CONC_WINDOW_MS / 3600000) + 'h (second machine — review + suspend/revoke if shared)'); } catch {}
          _lastSeenSaved.set(license, Date.now()); ks.save(db, { cas: true });
        }
      }
    } catch (e) { try { console.error('hwid-concurrency:', e.message); } catch {} }
    return res.json({ valid: false, message: 'License is already active on another device' });
  }
  rec.lastSeen = Date.now(); // always current in the in-memory (cached) store
  // ★2026-08-15 telemetry — PER-BRAND so ONE client running all 4 brand-apps (same key + hwid, separate userData each,
  // reporting on their own cycles) shows a COMBINED total instead of the apps overwriting each other's counts. `brand` is
  // client-controlled and becomes an object key → sanitize HARD: strip to [a-z0-9-] (removes the underscores in __proto__),
  // cap length, and reject the prototype-pollution names. Prune brands not seen in 14 days so a client that stopped running
  // one app doesn't inflate the total forever. Bounded (a handful of brands per key). list-keys.js sums rec.apps.
  try { // ★2026-08-16 OUTER GUARD: wrap the ENTIRE telemetry + clone-detection tail so a field/type error can NEVER 500 the license gate. (brand was undeclared here → ReferenceError on every re-validation → clients fell to offline grace → seats locked out ~7 days after activation.) On error: log + fall through to the grant; the seat stays valid, only this request's telemetry/flag update is skipped.
  if (ver) rec.lastVersion = ver; // keep the most-recent version at top level (backward-compat + display)
  const _sb = ks.recordAppTelemetry(rec, brand, { ver, acc, grp }, rec.lastSeen); // per-brand aggregate → combined per-client total (list-keys.js sums rec.apps)
  if (!_sb) { if (acc) rec.lastAccounts = acc; if (grp) rec.lastGroups = grp; } // no brand (older client) → flat single-app telemetry
  const _lsPrev = _lastSeenSaved.get(license) || 0;
  if (rec.lastSeen - _lsPrev > 3600000) { _lastSeenSaved.set(license, rec.lastSeen); ks.save(db, { cas: true }); } // persist at most hourly per license (mtime-cached load + this debounce = a re-validation flood costs ~0 scrypt/disk)
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
      if (!_wasFlagged) { try { ks.audit('flag', license, 'multi-ip fan-out=' + distinct + ' in 24h (possible MachineGuid clone) — review + suspend/revoke if shared'); } catch {} _lastSeenSaved.set(license, rec.lastSeen); ks.save(db, { cas: true }); }
    }
  } catch (e) { try { console.error('ip-track:', e.message); } catch {} }
  // ★RANK-2b (2026-08-16): same-hwid CONCURRENCY by validate RATE — the blind spot IP fan-out AND the bind-lock both miss: clones
  // behind ONE NAT with a reg-cloned MachineGuid present the SAME ip AND the SAME bound hwid, so every copy is accepted right here.
  // Their only tell is that N instances heartbeat → N× the validate rate one seat can produce. FLAG-ONLY (muddy: a heavy 4-brand
  // user with frequent restarts climbs too), NEVER auto-suspend. hwid == rec.hwid on this path, so this also keeps the bound machine
  // fresh in the log for the distinct-hwid check on the deny path.
  try {
    const { hits, distinctHwids } = ks.recordDeviceConcurrency(rec, hwid, rec.lastSeen, { windowMs: CONC_WINDOW_MS });
    if (hits >= RATE_HITS && distinctHwids <= 1) { // distinctHwids>1 is already covered by the stronger multi-hwid flag on the deny path
      const _wasFlagged = rec.flagged && rec.flagged.reason === 'multi-instance-rate';
      rec.flagged = { reason: 'multi-instance-rate', hits, at: rec.lastSeen };
      if (!_wasFlagged) { try { ks.audit('flag', license, 'multi-instance rate=' + hits + ' in ' + (CONC_WINDOW_MS / 3600000) + 'h (same-hwid clones behind one NAT? — review)'); } catch {} _lastSeenSaved.set(license, rec.lastSeen); ks.save(db, { cas: true }); }
    }
  } catch (e) { try { console.error('hwid-rate:', e.message); } catch {} }
  // ★LEAK-TRACE (2026-08-17): bind key→customer (from the per-build seat watermark) and FLAG a leaked build — a key checking
  // in from a build watermarked for a DIFFERENT customer than it first activated with = the build or the key crossed hands.
  // A customer's 4 brand builds share the same customer part (seatClient strips -app<n>), so a legit multi-brand seat never
  // trips. FLAG-only by default (a re-issued/renamed seat is benign — operator reviews via list-keys + key-audit.log);
  // LEAK_AUTOSUSPEND=1 opts into auto-suspend. Save is flag-once/debounced like the other flags → no scryptSync per request.
  try {
    if (seat) {
      rec.lastSeat = seat;
      const sc = ks.seatClient(seat);
      if (sc && !rec.seatClient) { rec.seatClient = sc; } // bind the customer baseline on first sighting
      else if (sc && rec.seatClient !== sc) {
        const _wasFlagged = rec.flagged && rec.flagged.reason === 'seat-mismatch';
        rec.flagged = { reason: 'seat-mismatch', expected: rec.seatClient, got: sc, seat, at: rec.lastSeen };
        if (LEAK_AUTOSUSPEND && !rec.suspended) {
          rec.suspended = true; rec.suspendMessage = 'License suspended — this build was issued to a different customer (auto). Contact support.';
          try { ks.audit('suspend', license, 'AUTO seat-mismatch expected=' + rec.seatClient + ' got=' + sc + ' (LEAK_AUTOSUSPEND) — REVERSIBLE: suspend.js --lift'); } catch {}
          _lastSeenSaved.set(license, rec.lastSeen); ks.save(db, { cas: true });
        } else if (!_wasFlagged) {
          try { ks.audit('flag', license, 'SEAT MISMATCH expected=' + rec.seatClient + ' got=' + sc + ' seat=' + seat + ' (leaked build / shared key — review + revoke/suspend)'); } catch {}
          _lastSeenSaved.set(license, rec.lastSeen); ks.save(db, { cas: true });
        }
      }
    }
  } catch (e) { try { console.error('seat-track:', e.message); } catch {} }
  } catch (e) { try { console.error('validate telemetry (non-fatal):', e && e.message); } catch {} } // ★2026-08-16 OUTER guard close: telemetry/persist/clone-flag can never break the grant
  return res.json(grant());
});

// Admin view of all keys.
app.get('/api/keys', rateLimiter({ windowMs: 60000, max: 20, name: 'keys' }), adminAuth, (_req, res) => {
  try { res.json(ks.load()); } catch (e) { res.status(503).json({ error: 'key store unavailable: ' + e.message }); }
});

// ★2026-09-01 (anti-theft hunt — operator CONTROL PANEL): a browser-friendly, live, read-only admin dashboard at GET /admin.
// Guarded by the SAME ADMIN_TOKEN as /api/keys but via HTTP BASIC auth (a browser can't send a Bearer header on a plain page
// navigation) — any username, the ADMIN_TOKEN as the password, constant-time compared (safeEq). Server-RENDERED (no client JS,
// no token in any URL/log), rate-limited, meta-refreshed. License keys are MASKED (first4…last4) so a screenshot/shoulder-surf
// can't leak a full key — the full store stays behind /api/keys / list-keys.js. Read-only: it never mutates the store.
function adminBasic(req, res, next) {
  const token = process.env.ADMIN_TOKEN;
  if (!token) return res.status(403).type('text/plain').send('admin disabled — set ADMIN_TOKEN on the server');
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/.exec(String(req.get('authorization') || ''));
  let pass = '';
  if (m) { try { const dec = Buffer.from(m[1], 'base64').toString('utf8'); const i = dec.indexOf(':'); pass = i >= 0 ? dec.slice(i + 1) : dec; } catch {} } // Basic base64(user:PASS) → the ADMIN_TOKEN is PASS (may contain colons)
  if (!pass || !safeEq(pass, token)) { res.set('WWW-Authenticate', 'Basic realm="za-admin", charset="UTF-8"'); return res.status(401).type('text/plain').send('Authentication required'); }
  next();
}
function _escH(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function _ago(ms) { if (!ms) return '—'; const s = Math.max(0, Math.floor((Date.now() - Number(ms)) / 1000)); if (s < 60) return s + 's'; if (s < 3600) return Math.floor(s / 60) + 'm'; if (s < 86400) return Math.floor(s / 3600) + 'h'; return Math.floor(s / 86400) + 'd'; }
function renderAdminHtml(db) {
  const now = Date.now();
  const keys = Object.keys(db || {}).sort((a, b) => String((db[a] && db[a].note) || '').localeCompare(String((db[b] && db[b].note) || '')));
  let active = 0, flagged = 0, suspended = 0, revoked = 0, totAcc = 0, totGrp = 0;
  const rows = keys.map((k) => {
    const r = db[k] || {};
    const isExp = r.expires && r.expires < now;
    const status = r.revoked ? 'revoked' : r.suspended ? 'suspended' : isExp ? 'expired' : 'active';
    if (status === 'active') active++;
    if (r.revoked) revoked++; if (r.suspended) suspended++;
    const fl = r.flagged && r.flagged.reason; if (fl) flagged++;
    const t = ks.sumAppTelemetry ? ks.sumAppTelemetry(r) : { acc: r.lastAccounts || 0, grp: r.lastGroups || 0, apps: 0 };
    totAcc += Number(t.acc) || 0; totGrp += Number(t.grp) || 0;
    const mask = k.length > 9 ? (k.slice(0, 4) + '…' + k.slice(-4)) : k;
    const flTxt = fl ? (r.flagged.reason === 'seat-mismatch' ? ('seat≠' + _escH(r.flagged.got || '')) : (r.flagged.reason + (r.flagged.ips ? ' ' + r.flagged.ips + 'ip' : r.flagged.hwids ? ' ' + r.flagged.hwids + 'hw' : ''))) : '';
    const ip24 = Array.isArray(r.ipLog) ? r.ipLog.filter((e) => e && now - Number(e.ts) <= 86400000).length : 0;
    return '<tr class="s-' + status + (fl ? ' fl' : '') + '">'
      + '<td>' + _escH(r.note || '—') + '</td><td class="dim">' + _escH(r.seatClient || '—') + '</td>'
      + '<td><code>' + _escH(mask) + '</code></td><td>' + _escH(r.tier || 'std') + '</td>'
      + '<td class="st">' + status + '</td><td>' + (r.hwid ? '<code>' + _escH(String(r.hwid).slice(0, 8)) + '…</code>' : '<span class="dim">unbound</span>') + '</td>'
      + '<td>' + _ago(r.lastSeen) + '</td><td>' + _escH(r.lastVersion || '?') + '</td>'
      + '<td class="num">' + (Number(t.acc) || 0) + '</td><td class="num">' + (Number(t.grp) || 0) + '</td>'
      + '<td class="num">' + (ip24 || '') + '</td><td class="fl">' + flTxt + '</td></tr>';
  }).join('');
  return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta http-equiv="refresh" content="45"><title>za-post · licenses</title><style>'
    + ':root{color-scheme:dark}body{background:#0e1116;color:#d7dde3;font:13px/1.5 -apple-system,Segoe UI,system-ui,sans-serif;margin:0;padding:20px}'
    + 'h1{font-size:15px;margin:0 0 4px}.sub{color:#8b95a1;font-size:12px;margin-bottom:14px}'
    + 'table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{text-align:left;padding:6px 9px;border-bottom:1px solid #1c2230;white-space:nowrap}'
    + 'th{color:#8b95a1;font-weight:600;position:sticky;top:0;background:#0e1116}tr.fl{background:#2a1d0e}'
    + 'td.st{text-transform:uppercase;font-size:11px}tr.s-active td.st{color:#4ade80}tr.s-revoked td.st{color:#f87171}tr.s-suspended td.st{color:#fbbf24}tr.s-expired td.st{color:#8b95a1}'
    + 'td.fl{color:#fbbf24}.num{text-align:right;font-variant-numeric:tabular-nums}.dim{color:#8b95a1}code{color:#93c5fd;font:12px ui-monospace,Consolas,monospace}'
    + '</style></head><body><h1>za-post · license control panel</h1><div class="sub">'
    + keys.length + ' keys · ' + active + ' active · ' + suspended + ' suspended · ' + revoked + ' revoked · ' + flagged + ' ⚠ flagged · Σ ' + totAcc + ' accounts / ' + totGrp + ' groups · '
    + _escH(new Date(now).toISOString().replace('T', ' ').slice(0, 19)) + ' UTC · auto-refresh 45s</div>'
    + '<table><thead><tr><th>Customer</th><th>Seat</th><th>Key</th><th>Tier</th><th>Status</th><th>Machine</th><th>Seen</th><th>Ver</th><th>Acc</th><th>Grp</th><th>IP/24h</th><th>Flag</th></tr></thead><tbody>'
    + (rows || '<tr><td colspan="12" class="dim">no keys</td></tr>') + '</tbody></table></body></html>';
}
app.get('/admin', rateLimiter({ windowMs: 60000, max: 60, name: 'admin' }), adminBasic, (_req, res) => {
  let db; try { db = ks.load(); } catch (e) { return res.status(503).type('text/plain').send('key store unavailable: ' + ((e && e.message) || e)); }
  res.set('Cache-Control', 'no-store').type('text/html').send(renderAdminHtml(db));
});

const PORT = process.env.PORT || 3509;
if (!ks.isEncryptedAtRest()) console.warn('⚠️  KEYS_ENCRYPTION_KEY is not set — the key store is stored in PLAINTEXT. Set it to encrypt keys.json at rest (see DEPLOY-COOLIFY.md).');
if (process.env.MIN_CLIENT_VERSION) console.warn('⚠️  VERSION GATE ACTIVE: MIN_CLIENT_VERSION=' + process.env.MIN_CLIENT_VERSION + ' — EVERY client reporting a lower version is denied at its next check (no offline grace). Ensure this is ≤ the version you have actually shipped, or the whole fleet locks out.');
// ★2026-08-16: explicit error handler — any unhandled route throw returns a GENERIC 500 with no stack/message. With
// NODE_ENV unset, Express's default handler put err.stack in the response body; on the unauthenticated /api/validate that
// leaked file paths + internals. Defense-in-depth alongside the per-handler try/catch and NODE_ENV=production.
app.use((err, _req, res, _next) => { try { console.error('unhandled:', err && err.message); } catch {} if (res.headersSent) return; try { res.status(500).json({ valid: false, message: 'Server error' }); } catch {} });

app.listen(PORT, '0.0.0.0', () => console.log('Za Post license server listening on :' + PORT + (ks.isEncryptedAtRest() ? ' (key store encrypted)' : '')));
