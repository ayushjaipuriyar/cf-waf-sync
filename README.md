# cf-waf-sync ☁️

**TypeScript Cloudflare Worker cron that keeps [sefinek/Cloudflare-WAF-Expressions](https://github.com/sefinek/Cloudflare-WAF-Expressions) in sync — no VPS, no PM2.**

The Worker runs scheduled (`0 9,15,18,22 * * *`) and pushes **WAF Custom Rules** (Parts 1–5) + **IP List** (`sefinek_cf_waf` merged from `ip-blocklist.txt` + [SniffCat](https://sniffcat.com) + [AbuseIPDB](https://www.abuseipdb.com)) to `http_request_firewall_custom`. WAF does the blocking; Worker only updates.

> Ported from `sefinek/Cloudflare-WAF-Expressions` `index.js` / `data/services/cloudflare/updateWAFRules.js` + `syncIPList.js` — `fetch` + `scheduled` instead of `axios` + `cron` + `simple-git` + `PM2`.

---

## Features

- **WAF Custom Rules** 5 parts (suspicious paths, malicious extensions, unwanted bots, ancient browsers + IP list, deprecated browsers) — `MAX_EXPRESSION_LENGTH 4096`, `RULE_CAPS` per plan, `normalize()` diff, preserves user rules
- **IP List** `sefinek_cf_waf` (10k Free cap auto-handled, trims AbuseIPDB tail) — cursor pagination, bulk ops
- **Zone-scoped tokens** (`cfut_...` with `CF_ZONE_IDS`/`CF_ZONE_NAMES` stub) and **Account tokens** (`cfat_...` with `Filter Lists:Edit` + `WAF:Edit`) — adaptive: `cfut_...` auto-strips `ip.src in $...` if list unavailable, `cfat_...` syncs full list
- **Allowlist** for public CDNs (`media-cdn1.seabuddy.co` default via `ALLOWLIST` → `not (allowlist) and (part)`)
- **Integrations** SniffCat (`X-Secret-Token`) + AbuseIPDB (`Key`), `PHP_SUPPORT`/`WORDPRESS_SUPPORT` toggles, `EXCLUDED_ZONES`
- **Observability** `GET /health`, `GET /sync?dryRun=1` (no auth), `POST /sync` (Bearer)

## Quick start

```bash
npm install

# required secrets
npx wrangler secret put CF_API_TOKEN   # cfat_... (Account) or cfut_... (zone-scoped)
npx wrangler secret put CF_ACCOUNT_ID  # 32-char hex from dash.cloudflare.com/<id>/

# optional intel (recommended)
npx wrangler secret put SNIFFCAT_API_TOKEN
npx wrangler secret put ABUSEIPDB_API_KEY

npx wrangler deploy
```

`wrangler.toml` `[vars]`:

```toml
CF_IP_BLOCKLIST_NAME = "sefinek_cf_waf" # "" to disable list
ALLOWLIST = 'http.host eq "media-cdn1.seabuddy.co"'
PHP_SUPPORT = "false"
WORDPRESS_SUPPORT = "false"
CF_ZONE_IDS = "0115c6fc4aab62dff1c8c1730b17cea9" # for cfut_... zone-scoped
CF_ZONE_NAMES = "seabuddy.co"
SNIFFCAT_CONFIDENCE_MIN = "80"
SNIFFCAT_LIMIT = "2000"
ABUSEIPDB_CONFIDENCE_MIN = "75"
ABUSEIPDB_LIMIT = "8000"
```

To sync all zones with a `cfat_...`, clear `CF_ZONE_IDS`/`CF_ZONE_NAMES`.

## Dev

```bash
npx wrangler dev --test-scheduled
curl "http://localhost:8787/__scheduled?cron=0+9+*+*+*"
curl "http://localhost:8787/sync?dryRun=1"
curl -X POST "http://localhost:8787/sync" -H "Authorization: Bearer $CF_API_TOKEN"
```

## Token perms

Create **Account API Token** (`cfat_...`) at `dash.cloudflare.com/<account_id>/config/api/tokens` → Custom:

- **Account** `THE SOCIAL MARITIME PTE LTD` → `Filter Lists:Edit`, `Account:Read`
- **Zone** `seabuddy.co` (or All zones) → `WAF:Edit`, `Zone:Read`

For **WAF-only** with `cfut_...` (zone `WAF:Edit` only), IP list will be skipped and Part 4's `ip.src in $...` stripped automatically — WAF Parts 1–5 still sync.

## How it differs from original

| Original (`sefinek`) | This Worker |
|---|---|
| Node 20+ `cron` `PM2` `simple-git` `nodemailer` `axios` | `fetch` + `scheduled` |
| `rules/expressions.md` git-pulled | Bundled `src/assets/bundled.ts` or live `RULES_SOURCE_URL` |
| `GET /zones` enumeration | + stubbed `CF_ZONE_IDS` for `cfut_...` |
| `syncIPList` throws on auth | Skipped with warning, WAF retry without list |

## Similar projects

- `DavidJKTofan/cf-icloud-private-relay-ip-list-manager` (Worker cron IP List)
- `klinge/crowdsec-cloudflare-sync`
- `homieyangg/cloudflare_waf_multi_zone_ci_example`

## Acknowledgements

- Upstream rules & lists: [sefinek/Cloudflare-WAF-Expressions](https://github.com/sefinek/Cloudflare-WAF-Expressions) (GPL-3.0)
- Live on `seabuddy.co` (`0115c...`, Pro, 20-rule cap) — `https://cf-waf-sync.super-dream-1056.workers.dev`

## License

GPL-3.0 — same as upstream.
