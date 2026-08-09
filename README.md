# License Server (VPS side)

The desktop app's license gate (`../lib/license.js`) validates keys against this server
and binds each key to one machine (HWID). Deploy this on your VPS (the one at
`144.91.127.7:3509`, or any host the app's License → Settings points to).

## Deploy
```bash
# on the VPS, in this folder
npm init -y && npm i express
ADMIN_TOKEN=pick-a-secret node license-server.js     # listens on :3509 (or $PORT)
# keep it running with pm2/systemd, e.g.:  pm2 start license-server.js --name za-license
```
If the existing server at `:3509` is already serving the old `/api/automation-script`,
either add the `/api/validate` route from `license-server.js` into it, or run this on a
different port and point the app there (License screen → ⚙ Settings → Server URL).

## Manage keys
```bash
node gen-key.js "customer name"        # new key, no expiry  -> prints the key
node gen-key.js "trial" 7              # new key, expires in 7 days
node revoke.js  AAAA-BBBB-CCCC-DDDD    # revoke a key (app shows revoked.html)
node revoke.js  AAAA-... --unbind      # revoke + clear machine binding
node revoke.js  AAAA-... --restore     # un-revoke
curl -H "Authorization: Bearer $ADMIN_TOKEN" "http://localhost:3509/api/keys"   # list all keys (Bearer only — the ?admin= query fallback was removed so the token can't leak into proxy/access logs)
```

## How it works
- App POSTs `{ license, hwid }` to `/api/validate` on activation and each launch.
- First activation **binds** the key to that machine's HWID; later launches from a
  different machine are refused (`License already in use on another device`).
- `revoked` keys return `{ revoked: true }` → the app shows the "revoked" screen.
- If the server is **unreachable**, the app falls back to an offline allow-list (only the
  pre-embedded owner key works offline; customer keys require the server).

## Keys
- `keys.json` is the store (seeded with your **owner key**). Back it up.
- The owner key also works offline (its hash is embedded in the client).
- The HMAC `SERVER_SECRET` from setup is only needed if you switch to signed-token keys later.

## Click tracking — authentic clean links (`/r/*`)   *(added 2026-08-01)*
The app can publish **authentic** tracked links that look like a real article instead of a cloaked redirect:

```
old (still supported):   https://<host>/r?g=123&a=ab12&p=42&c=health&u=https://blog.com/mix-these-3
new  'clean' mode:       https://<host>/r/mix-these-3/<opaque-token>
```

The real article slug is visible; the analytics `{g,a,p,c}` ride inside the opaque token; **the destination URL is never in the link**. On a click, the `/r/*` route decodes the token, rebuilds the destination as `CLICK_DEST_ORIGIN + '/' + slug` (so it can **never** leave your blog — no open-redirect), logs the click (same `clicks.jsonl`, same per-group/account/post/category totals), and 302s to the real article. The codec is `clickToken.js` (a byte-compatible twin of the app's `lib/clickToken.js`).

**Deploy:** just redeploy this folder — the new `clickToken.js` + `/r/*` route are included. **No new env vars**: it reuses the `CLICK_DEST` you already set for `/r` (its origin/host are the rebuild base + allow-list; `CLICK_HOSTS` still extends the allow-list). Verify after deploy:
```bash
# a real token comes from the app; this just proves the route is live (an undecodable token 302s to CLICK_DEST):
curl -sI "https://<host>/r/mix-these-3/not-a-real-token" | grep -i location   # -> your CLICK_DEST
```
**In the app:** Groups tab → Click tracking → **Clean links**, set the base to your redirect origin (e.g. `https://<host>`, no `/r`), keep the Clicks API + read-token as-is, then **Refresh clicks** reads counts exactly as Local mode did.
