# Deploy the license server on Hostinger VPS via Coolify

This folder is the license-validation server for the desktop app. The app POSTs
`{ license, hwid }` to `/api/validate` on activation and each launch.

## The one thing that matters most
`keys.json` (your keys + machine bindings) **must live on a persistent volume**, or it
resets every redeploy and all activations are lost. The Dockerfile sets `KEYS_PATH=/data/keys.json`
— you just mount a volume at **`/data`** in Coolify (Step 4).

The real `keys.json` is **gitignored** (it holds your owner key — never goes to GitHub). The
volume starts empty; the server seeds your owner key on first boot from the **`OWNER_KEY`** env
var (Step 5). Customer keys are created later with `gen-key.js` on the server.

---

## Step 1 — Repo  ⚠️ TWO COPIES OF THIS CODE EXIST
Coolify deploys from the **standalone** repo `github.com/daseknahri/vps-server`, whose contents are this
folder's files at its root. This `vps-server/` folder inside the app project is only a working copy.

**Editing here deploys nothing.** Changes reach production only when copied into that other repo. This has
already cost one cycle: the licence-signing server was written here and Coolify was redeployed, so it
rebuilt the *old* code — the deploy looked perfectly healthy while the new server had never shipped, and
`curl` could not tell the difference. After changing anything here, copy it across, redeploy, and confirm
with `node scripts/verify-license-server.js <url> <key>` before shipping any client build.

The real `keys.json` is gitignored, so no secret is published — but keep the repo **private**
anyway, since it holds your sellable app source.

## Step 2 — New resource in Coolify
- **+ New → Application → Private Repository** → pick `daseknahri/vps-server`, branch `main`.
- **Base Directory** = `/` (the repo root already *is* the server folder).
- **Build Pack: Dockerfile** (auto-detected at the repo root). (Nixpacks also works via `package.json` + start script, but Dockerfile is the most predictable.)

## Step 3 — Port
- Set **Ports Exposes = `3509`** (the app listens on `PORT`, default 3509; the Dockerfile sets it).
- Coolify's proxy (Traefik) maps your domain → this port.

## Step 4 — Persistent storage (critical)
- In the resource → **Storages / Persistent Storage → Add**:
  - **Name:** `license-data`
  - **Mount Path:** `/data`
- This makes `/data/keys.json` survive redeploys.

## Step 5 — Environment variables
- **`LICENSE_SIGNING_KEY`** = base64 of the PKCS8 PEM private key (from `node gen-signing-key.js`).
  **The server refuses to boot without it.** Clients from v1.0.253 on reject any grant that is not signed by
  it, so an unsigned server activates nobody. Its public half is compiled into the client — replacing this
  value locks out every already-shipped build, so set it once and never rotate it casually.
- `OWNER_KEY` = your owner license key — seeded into the volume on first boot.
  (Kept in Coolify's env, not in Git, so the secret never gets published.)
- `ADMIN_TOKEN` = a long secret (protects `GET /api/keys`).
- `KEYS_PATH` = `/data/keys.json` (already set by the Dockerfile; add it here too if using Nixpacks).
- (Optional) `PORT` = `3509`.
- **Click tracking (optional — the desktop app's per-group / per-account link clicks):**
  - `CLICK_DEST` = the offer URL that `/r` redirects clicks to. **Must equal the destination link that's in your posts** —
    the app matches that URL to know what to swap for the tracked link. Server-side (not a query param) so `/r` can never be
    abused as an open redirect.
  - `CLICK_TOKEN` = a random secret. The desktop app sends it as `Authorization: Bearer <CLICK_TOKEN>` to read `GET /api/clicks`.
    Keep it SEPARATE from `ADMIN_TOKEN` (least privilege — the app never needs key-store access).
  - `CLICKS_PATH` = `/data/clicks.jsonl` is the default (already on the persistent volume — survives redeploys). Set it only to relocate.
  - ⚠️ Click tracking adds a **new file** `clicks.js` and two routes in `license-server.js`. Per Step 1, both must be copied
    into the `daseknahri/vps-server` deploy repo — editing this working copy ships nothing.

## Step 6 — Domain + HTTPS
- Coolify gives a domain (or set your own subdomain, e.g. `license.yourdomain.com`) and issues
  **auto‑HTTPS** via Let's Encrypt. Recommended — the app can then use `https://license.yourdomain.com`.
- No domain? Use the VPS IP: the endpoint is `http://<vps-ip>:3509` (open that port in Hostinger's firewall).

## Step 7 — Deploy & verify
Click **Deploy**. Then test (replace the URL with your domain/IP):
```bash
# Must return valid:true AND a "token" + "sig" pair. Without those two fields the server is running
# unsigned, and every v1.0.253+ client will refuse it — check LICENSE_SIGNING_KEY before shipping.
curl -X POST https://license.yourdomain.com/api/validate \
  -H "Content-Type: application/json" \
  -d '{"license":"YOUR-OWNER-KEY","hwid":"test-machine-1","nonce":"n1"}'

# list keys (admin) — header only; the ?admin= query param was REMOVED (it leaked the token into
# Nginx/Cloudflare access logs).
curl -H "Authorization: Bearer YOUR_ADMIN_TOKEN" https://license.yourdomain.com/api/keys
```

**Click tracking (if you set `CLICK_DEST` / `CLICK_TOKEN`):**
```bash
# The redirect — must return HTTP 302 with Location: <your CLICK_DEST>. A real browser hitting this URL is
# logged as a click; Facebook's link-preview crawler (facebookexternalhit) is filtered out and NOT counted.
curl -sI "https://license.yourdomain.com/r?g=test&a=test"

# The counts the desktop app reads — Bearer header only. Returns { total, byGroup, byAccount, byGroupAccount }.
curl -s -H "Authorization: Bearer YOUR_CLICK_TOKEN" https://license.yourdomain.com/api/clicks
```
Then in the app: **Groups tab → Click tracking → Local**, set Destination (= `CLICK_DEST`), Redirect base
(`https://license.yourdomain.com/r`), Clicks API (`https://license.yourdomain.com/api/clicks`) and the token, and hit
**Refresh clicks**. Every posted link carries `&a=<account>`, so `byAccount` populates automatically for per-account stats.

## Step 8 — Point the desktop app at this server
Two ways:
1. **Bake it in** (for the installer): in `../lib/license.js`, set
   `const DEFAULT_SERVER = 'https://license.yourdomain.com';`
2. **At runtime**: open the app's **License screen → ⚙ Settings → Server URL** and enter the URL
   (this calls `update-server-url`, no rebuild needed).

## Step 9 — Manage keys (via Coolify terminal)
Open the resource's **Terminal** in Coolify and run:
```bash
KEYS_PATH=/data/keys.json node gen-key.js "customer name"     # new key
KEYS_PATH=/data/keys.json node gen-key.js "trial" 7           # 7-day key
KEYS_PATH=/data/keys.json node revoke.js  AAAA-BBBB-CCCC-DDDD # revoke
```
(They read/write the same `/data/keys.json` the server uses.)

---

## Multi-blog click tracking (2026-08-08)

Each of your blogs fronts its OWN tracked links: the app publishes `https://go.<blog>/r/<article-slug>/<token>`, the
server resolves the incoming host (`go.<blog>`) back to that blog's origin and 302s to the real article. One VPS, N
blog-branded hosts, one central clicks log. Do these once per blog.

### A. Ship the code (the #1 gotcha — see Step 1)
The multi-blog change adds **`blogMap.js`** and edits **`license-server.js`** + **`clicks.js`**. Coolify deploys from
`daseknahri/vps-server`, NOT this working copy — copy all three (plus `blogs.example.json`) into that repo, commit, push,
then redeploy. Editing this folder ships nothing.

### B. DNS — one record per blog
For each blog, create a subdomain that points at the VPS (same box the license server runs on):
```
go.recipeblog.com    A     <YOUR_VPS_IP>      # from Hostinger → your VPS. (CNAME → recipes.ibnbatoutaweb.com also works for a subdomain.)
```
Repeat for every blog (`go.travelblog.com`, …). Let propagation finish (`nslookup go.recipeblog.com` → your VPS IP).

### C. Coolify — add each go.<blog> as a domain
On the vps-server resource → **Domains**, add every tracking host so Traefik routes it AND issues its Let's Encrypt
cert (HTTP-01, automatic). Space/comma-separate them:
```
https://recipes.ibnbatoutaweb.com, https://go.recipeblog.com, https://go.travelblog.com
```
Keep your existing license/clicks domain in the list. Redeploy (or let Coolify apply) and wait for the padlock on each
`https://go.<blog>/health`.

### D. The blog map — tracking host → blog origin
Map each `go.<blog>` to that blog's real origin. **Preferred (no redeploy):** create the file on the persistent volume
via the Coolify **Terminal**:
```bash
cat > /data/blogs.json <<'JSON'
{
  "go.recipeblog.com": "https://recipeblog.com",
  "go.travelblog.com": "https://travelblog.com"
}
JSON
```
Edit that file any time to add a blog — it is mtime-cached, picked up within a request, no redeploy. **Alternative**
(config-as-env): set `CLICK_BLOGS` to the same JSON as one line and redeploy. `blogs.json` wins if both exist. Your
existing `CLICK_DEST` / `CLICK_TOKEN` / `CLICK_HOSTS` stay as-is — they remain the fallback + the shared offer, and keep
already-live links resolving.

### E. Point the app at your blogs
App → **Settings → Tracking**:
- Mode = **Clean multi-blog links**
- **Blog list** (one per line — must match the `blogs.json` keys' blogs):
  ```
  recipeblog.com
  travelblog.com
  ```
  (Each `recipeblog.com` auto-publishes as `go.recipeblog.com`. Use `site > track.host` only if your tracking host
  isn't `go.<site>`.)
- **Clicks API** = `https://recipes.ibnbatoutaweb.com/api/clicks` · **token** = your `CLICK_TOKEN`

### F. Smoke-test ONE blog before a full run
Mint a test token (Coolify Terminal, in `/app`) and hit a REAL article slug on that blog:
```bash
TOK=$(node -e "console.log(require('./clickToken').encodeClick({g:'smoke',a:'smoke',p:'smoke',c:'smoke'}))")
# expect: HTTP/1.1 302 + Location: https://recipeblog.com/<a-real-slug>
curl -sI "https://go.recipeblog.com/r/<a-real-slug>/$TOK"
# expect the click to appear (total ≥ 1, and byBlog has go.recipeblog.com's origin host)
curl -s -H "Authorization: Bearer <YOUR_CLICK_TOKEN>" "https://recipes.ibnbatoutaweb.com/api/clicks" | head -c 400
```
Green on both → the app's **Refresh clicks** will now populate. Only then roll out to a full run.

### Rollback
Set Tracking back to **Off** in the app (posts the real links untracked, instantly). The server change is additive — the
legacy `/r` + single-origin routes are untouched, so nothing already posted breaks.

---

### Notes
- Redeploys keep your keys (volume at `/data`). `OWNER_KEY` only seeds the owner key into an
  empty volume on first run — it never overwrites existing keys or bindings.
- Health: `GET /api/validate` with no body returns `{valid:false}` — useful for a Coolify healthcheck
  (or add a dedicated `/health` route later).
- If you keep your old VPS too, you can run both; the app talks to whichever URL it's pointed at.
