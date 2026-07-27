// vps-server/clicks.js — per-group / per-account click tracking store for the /r redirect.
// Append-only JSONL on the PERSISTENT /data volume (survives redeploys, same as keys.json). One line per real click:
//   { ts, g:<groupId>, a:<account>, p:<postId>, ip, ua }
// Read side aggregates on demand — fine for this scale (thousands/day); add rollup if it ever grows to millions.
'use strict';
const fs = require('fs');
const path = require('path');

const FILE = String(process.env.CLICKS_PATH || '/data/clicks.jsonl');

function _ensureDir() { try { fs.mkdirSync(path.dirname(FILE), { recursive: true }); } catch {} }

// Fire-and-forget: a logging failure must NEVER break the redirect the human is waiting on.
function logClick(rec) {
  try { _ensureDir(); fs.appendFile(FILE, JSON.stringify(rec) + '\n', () => {}); } catch {}
}

// Aggregate every click into per-group, per-account, and per-(group,account) totals. Reads the whole file; unreadable /
// non-JSON lines are skipped (never throws). `since` (ISO string, optional) limits to clicks at/after that instant.
function aggregate(since) {
  let raw = '';
  try { raw = fs.readFileSync(FILE, 'utf8'); } catch { return { total: 0, byGroup: {}, byAccount: {}, byGroupAccount: {}, since: since || null }; }
  const byGroup = {}, byAccount = {}, byGroupAccount = {}, byPost = {}, byCategory = {};
  let total = 0;
  for (const line of raw.split('\n')) {
    if (!line) continue;
    let r; try { r = JSON.parse(line); } catch { continue; }
    if (since && String(r.ts || '') < since) continue;
    total++;
    const g = r.g != null ? String(r.g) : '';
    const a = r.a != null ? String(r.a) : '';
    const p = r.p != null ? String(r.p) : '';
    const c = r.c != null ? String(r.c) : '';
    if (g) byGroup[g] = (byGroup[g] || 0) + 1;
    if (a) byAccount[a] = (byAccount[a] || 0) + 1;
    if (p) byPost[p] = (byPost[p] || 0) + 1;
    if (c) byCategory[c] = (byCategory[c] || 0) + 1; // c = post CATEGORY (post-set) — stable across runs
    if (g && a) { const k = g + '|' + a; byGroupAccount[k] = (byGroupAccount[k] || 0) + 1; }
  }
  return { total, byGroup, byAccount, byGroupAccount, byPost, byCategory, since: since || null };
}

module.exports = { logClick, aggregate, FILE };
