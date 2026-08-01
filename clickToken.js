'use strict';
// TWIN of ../lib/clickToken.js — kept as a SELF-CONTAINED copy because the Docker image only bundles vps-server/
// (see Dockerfile `COPY . .`), so the server can't require ../lib. tests/click-token.test.js asserts this file and
// lib/clickToken.js are cross-compatible (app encodes → VPS decodes, and back), so the two copies can never drift.
//
// AUTHENTIC link shape:   https://<redirect-host>/r/<slug>/<token>
//   <slug>  = the destination article's PATH (visible → the link reads like a real article, not a tracker)
//   <token> = base64url(JSON) of the analytics { g, a, p, c } (+ optional dest query q / fragment f)
//
// The destination is rebuilt here as <destOrigin>/<slug>(?q)(#f) with destOrigin FIXED (CLICK_DEST_HOST), so the
// redirect can never leave the allow-listed host regardless of the token — hence the token is UNSIGNED (it carries
// only analytics labels, never the redirect target; forging one merely mislabels a click).
function encodeClick(o) {
  try {
    const p = {};
    for (const k of ['g', 'a', 'p', 'c']) { const v = o && o[k]; if (v != null && v !== '') p[k] = String(v).slice(0, 120); }
    if (o && o.q) p.q = String(o.q).slice(0, 400); // destination query string, INCLUDING its leading '?'
    if (o && o.f) p.f = String(o.f).slice(0, 200); // destination fragment, INCLUDING its leading '#'
    return Buffer.from(JSON.stringify(p), 'utf8').toString('base64url');
  } catch { return ''; }
}
function decodeClick(token) {
  try {
    const o = JSON.parse(Buffer.from(String(token || ''), 'base64url').toString('utf8'));
    if (!o || typeof o !== 'object' || Array.isArray(o)) return null; // a normal slug word decodes to garbage → not JSON → null
    return o;
  } catch { return null; }
}
module.exports = { encodeClick, decodeClick };
