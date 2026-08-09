// vps-server/blogMap.js — MULTI-BLOG click routing (2026-08-08).
// The desktop app fronts each operator blog's tracked links with that blog's OWN redirect host (a subdomain, default
// go.<site>, that DNS-points here). A click arrives on Host = go.recipeblog.com; this maps it back to the blog's real
// origin (https://recipeblog.com) so /r/* can 302 to the genuine article on the right blog. One VPS, N blog-branded
// hosts, one central clicks log.
//
// SOURCE (first that resolves):
//   1. /data/blogs.json  (BLOGS_PATH override) — a plain JSON object { "<trackHost>": "<destOrigin>", ... }. On the
//      PERSISTENT /data volume so adding a blog is a file edit, NO redeploy. mtime-cached (an external edit is picked up).
//   2. CLICK_BLOGS env — the SAME JSON as a string, for a config-as-env deploy (used only when the file is absent).
// resolve(host) → the blog's destination ORIGIN (scheme+host, no trailing slash) or null. The caller rebuilds the
// destination against that origin and re-checks the host, so a bad map entry can never become an open redirect.
'use strict';
const fs = require('fs');
const path = require('path');

function blogsPath() { return process.env.BLOGS_PATH || '/data/blogs.json'; }

// Normalize a map into { <lowercased trackHost>: <clean origin> }. A value may be given as a full URL or a bare host;
// either way we reduce it to its origin. Malformed entries are dropped (never throw — a bad line must not break /r).
function _normalize(obj) {
  const out = {};
  if (!obj || typeof obj !== 'object') return out;
  for (const [k, v] of Object.entries(obj)) {
    const host = String(k || '').trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');
    if (!host || host.indexOf('.') < 0) continue;
    let originStr = String(v || '').trim();
    if (!/^https?:\/\//i.test(originStr)) originStr = 'https://' + originStr.replace(/^\/+/, '');
    let origin = '';
    try { origin = new URL(originStr).origin; } catch { continue; } // not a valid origin → skip this blog
    if (!origin || origin === 'null') continue;
    out[host] = origin;
  }
  return out;
}

// Env seed is parsed once (it can't change without a restart anyway).
let _envMap = null;
function _envSeed() {
  if (_envMap) return _envMap;
  let parsed = {};
  try { parsed = JSON.parse(String(process.env.CLICK_BLOGS || '').trim() || '{}'); } catch { parsed = {}; }
  _envMap = _normalize(parsed);
  return _envMap;
}

// mtime-cached file load (mirrors keystore.js F1): an unchanged file serves the cached, pre-normalized map; an external
// edit (new mtime) forces a re-read; a missing/corrupt file falls back to the env seed. Never throws.
let _cache = null, _cacheMtime = -1, _cacheFile = '';
function _fileMap() {
  const file = blogsPath();
  let st;
  try { st = fs.statSync(file); }
  catch { _cache = null; _cacheMtime = -1; _cacheFile = ''; return null; } // no file → caller uses the env seed
  if (_cache && _cacheFile === file && _cacheMtime === st.mtimeMs) return _cache;
  let map = null;
  try { map = _normalize(JSON.parse(fs.readFileSync(file, 'utf8'))); }
  catch { map = null; } // unreadable/corrupt → treat as absent (fall back to env), don't crash the redirect path
  _cache = map; _cacheMtime = map ? st.mtimeMs : -1; _cacheFile = map ? file : '';
  return map;
}

// The destination origin for an incoming tracking host, or null if this host isn't one of the operator's blogs.
function resolve(host) {
  const h = String(host || '').trim().toLowerCase().replace(/:\d+$/, '');
  if (!h) return null;
  const fileMap = _fileMap();
  const map = (fileMap && Object.keys(fileMap).length) ? fileMap : _envSeed();
  return map[h] || null;
}

// Every configured blog origin — the allow-list of hosts a rebuilt destination may land on.
function origins() {
  const fileMap = _fileMap();
  const map = (fileMap && Object.keys(fileMap).length) ? fileMap : _envSeed();
  return Object.values(map);
}

module.exports = { resolve, origins, blogsPath };
