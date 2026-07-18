# cti-expert — Web Pivot & Premium API Keys

**Languages:** English · [Tiếng Việt](README-apikeys.vi.md) · [中文](README-apikeys.zh-CN.md)

How to use **`/webpivot`** (web-infrastructure pivoting) and **`/apikeys`** (premium key management).
cti-expert works **100% keyless / free by default** — premium API keys only *upgrade* it, and it
keeps working with none set.

---

## TL;DR

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py

uv run "$AK"                              # status — what's configured (nothing needed to start)
uv run "$AK" set censys censys_pat_XXXX  # add a premium key (Censys example)
uv run "$AK" test censys                 # 🟢 valid / 🔴 invalid / 🟠 error
uv run "$AK" unlocks                      # what your keys now unlock

/webpivot https://suspicious-site.top    # use it — keys apply automatically
```

---

## 1. Where are the API keys stored? (the ONE file)

There is exactly **one** key file for cti-expert:

```
~/.claude/skills/cti-expert/.env          ( = $SKILL_DIR/.env )
```

- It is **created automatically** the first time you run `/apikeys set …` — it does **not** exist
  until then (so if you don't see it yet, that's normal).
- `chmod 600` + **gitignored** — never committed.

**The other `.env` files you saw are NOT cti-expert's key store** — ignore them. They are templates
that ship inside the *source* packages:

| File you saw | What it actually is |
|---|---|
| `WebPivot/.env.example`, `quarry/.env.example` | Example templates in the **original repos** (reference only) |
| `quarry/.env.docker.example` | quarry's Docker template |
| `scripts/webpivot/.env` (only if you made one) | Legacy back-compat path; the **skill-root `.env` is canonical** |

**Resolution order everywhere:** **environment variable → skill `.env` → keyless.** An environment
variable always overrides the file (handy on shared machines / CI).

---

## 2. Two ways to add or edit keys

### A) With the `/apikeys` command (recommended)

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py

# Censys needs a Personal Access Token, plus an optional Org ID:
uv run "$AK" set censys censys_pat_XXXXXXXXXXXX     # accepts the service id ("censys")…
uv run "$AK" set CENSYS_ORG_ID 1234-5678-org        # …or an exact ENV_VAR name
uv run "$AK" set CENSYS_API_SECRET censys_pat_XXXX  # (alias also accepted)

# Keep the secret out of shell history — pipe it on stdin instead:
printf %s "$MYKEY" | uv run "$AK" set censys

uv run "$AK" unset censys                            # remove a key
```

### B) Edit the `.env` file directly

The skill ships a **[`.env.example`](.env.example)** listing every supported key (all blank), each
with a note on what it unlocks and where to get it. Copy it and fill in the keys you have:

```bash
cp .env.example .env       # run from the skill root (~/.claude/skills/cti-expert)
```

Or just open `~/.claude/skills/cti-expert/.env` in any editor and add `KEY=VALUE` lines:

```dotenv
# cti-expert API keys — chmod 600, gitignored. Never commit.
CENSYS_API_KEY=censys_pat_XXXXXXXXXXXX
CENSYS_ORG_ID=1234-5678-org
SHODAN_API_KEY=your_shodan_key
```

Both methods write the **same** file. Run `uv run "$AK" status` to confirm what was picked up.

---

## 3. What does each key unlock?

Run `uv run "$AK" status --all` for the full catalog (17 services) or see
[`handbook/api-keys.md`](handbook/api-keys.md). The keyless/free path already covers most of these;
the key unlocks the higher-tier or reverse-lookup capability:

| Service | Env var | Unlocks |
|---|---|---|
| Shodan | `SHODAN_API_KEY` | `/webpivot`: reverse favicon **mmh3** → hosts; `/cert-pivot`: reverse **TLS cert fingerprint** → hosts |
| Censys | `CENSYS_API_KEY` (or `CENSYS_API_ID`+`CENSYS_API_SECRET`) | `/webpivot`: reverse favicon **MD5**; `/cert-pivot`: cert **fingerprint_sha256** → hosts |
| FOFA | `FOFA_KEY` (+`FOFA_EMAIL`) | `/webpivot`: `icon_hash` + tracker-body reverse |
| DNSLytics | `DNSLYTICS_API_KEY` | `/webpivot`: AdSense/GA ID → **sibling domains** |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | passive DNS, subdomains, DNS/WHOIS history |
| urlscan.io PRO | `URLSCAN_API_KEY` | authenticated DOM content search |
| WhoisXML | `WHOISXML_API_KEY` | current + historic + **reverse WHOIS** |
| Blockchair | `BLOCKCHAIR_API_KEY` | `/crypto-balance`: **lifetime received/sent flows** on more chains (keyless already gives balance + tx count) |
| Subscan | `SUBSCAN_API_KEY` | `/crypto-balance`: higher-rate **Polkadot (DOT)** lookups |
| Hudson Rock / IntelX / ChongLuaDao | `HUDSONROCK_API_KEY` / `INTELX_API_KEY` / `CHONGLUADAO_API_KEY` | breach / leak / darknet feeds; ChongLuaDao also powers `/email-hygiene` burner detection |
| GitHub · SerpAPI · BrightData · CertSpotter · ZoneCruncher | … | code discovery · dork automation · CT · liveDNS |

---

## 4. What workflow uses these keys? (and the keyless fallback)

Keys plug into `pivot_extract.py`'s **`enrich_live()`** stage, used by **`/webpivot`** (and by
**`/case`** for domain/URL targets):

1. **Extract** artifacts from the page — favicon hashes, GA/GTM/AdSense IDs, wallets, SaaS operator
   tokens, emails, DOM fingerprint.
2. **Keyless baseline — ALWAYS runs:** crt.sh (certificate transparency), HackerTarget passive DNS,
   anonymous urlscan.
3. **Premium — only for keys you've set:** Shodan (favicon mmh3 + cert fingerprint → hosts),
   Censys (favicon MD5 + cert SHA-256), FOFA, DNSLytics (GA/AdSense → sibling domains),
   SecurityTrails (passive DNS), urlscan-PRO, WhoisXML, Blockchair/Subscan (wallet flows for
   `/crypto-balance`). Each hit is attached to the pivot as `live_results` and shown in `--leads`.

> **New keyless correlation tools** (no key needed): `/rank-relations` (score same-operator
> siblings + noise denylist), `/cert-pivot` (cert SANs), `/pivot-suggest`, `/crypto-balance`,
> `/email-hygiene`, `/sensitive-paths`. Keys above only *enhance* them.

> **If no keys are set, everything still works exactly as before — keyless / free.** Each premium
> enricher is skipped when its key is absent, and any error (bad key, quota) degrades to a small
> note — it never breaks the run.

---

## 5. Does `/case` include webpivot by default?

**Yes — for domain / URL targets.** `/case example.com` runs `/webpivot` inside its **Acquire**
phase:

- **Keyless by default** (crt.sh + passive DNS + anonymous urlscan).
- **Upgrades automatically** when premium keys are set via `/apikeys`.
- It is **not** run for `username` / `phone` / person targets.
- Because `/webpivot` can fetch the target directly, for **hostile infrastructure** it prefers
  passive capture (urlscan / Wayback) — see [`techniques/web-pivot.md`](techniques/web-pivot.md).

You can also run it on its own: `/webpivot https://target.top`.

---

## 6. Workflow diagrams

**`/webpivot` + premium API-key flow** — how keys plug into the pivot:

![cti-expert /webpivot + premium API-key workflow](assets/workflow-apikeys.png)

**`/case` full pipeline (AEAD)** — where `/webpivot` and the keys fit in a full case:

![cti-expert /case pipeline](assets/workflow-case.png)

---

## 7. Security

- **Never commit `.env`** — it's gitignored (`.env` + `scripts/**/.env`).
- On shared machines / CI, prefer **environment variables** (they override the file and leave
  nothing extra on disk).
- `set <service> <KEY>` puts the key in your shell history — use the **stdin form**
  (`printf %s "$KEY" | uv run "$AK" set censys`) to avoid that.
- `/apikeys` output **always masks** key values (length + last 2 chars only).

---

## 8. Verify

```bash
AK=~/.claude/skills/cti-expert/scripts/apikeys/apikeys.py
uv run "$AK" status         # which keys are set + what they unlock
uv run "$AK" test censys    # live-probe: 🟢 valid / 🔴 invalid / 🟠 error / ⚪ no-test
uv run "$AK" path           # where the .env lives + permissions
```

---

## Credits

- **WebPivot** — the `/webpivot` tooling in `scripts/webpivot/` (favicon/tracker/wallet extraction, Wayback-GA, reverse-WHOIS, graph clustering) — by **[Zeroska](https://github.com/Zeroska)**, adapted for cti-expert.
- **cti-expert** by Hieu Ngo — [chongluadao.vn](https://chongluadao.vn).
