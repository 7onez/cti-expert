#!/usr/bin/env python3
"""
Stealer-Log Analyzer — CTI attribution, actor profiling & IOC extraction.

Walks a folder of infostealer logs (one sub-folder per infected host, mixed
families) and produces a CTI report that:
  * fingerprints the stealer family + reseller/traffer branding (banner & layout),
  * extracts attribution IOCs (Telegram/Jabber contacts, panel/C2 URLs, build IDs),
  * parses RAW artifacts — passwords, autofills, history, cookies — and
  * triages each log VICTIM vs OPERATOR/MULE so analysts can profile threat actors.

Raw credential/identity/browsing data is shown deliberately: in CTI, an actor's
own infected machine leaks their panels, aliases, and infrastructure. Handle the
output per your org's data-protection obligations (it contains third-party PII).

Recommended runner (zero setup, any OS): `uv run stealer_log_parse.py <log-folder> [out-dir]`
Stdlib-only — no dependencies, so plain `python3`/`py` works too.

Usage:
    uv run stealer_log_parse.py "C:\\path\\to\\logs"
    uv run stealer_log_parse.py /path/to/logs ./out
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import re
import json
import datetime
from collections import Counter, defaultdict

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# ── helpers ───────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)
TME_RE = re.compile(r"(?:t\.me/|telegram\.me/|@)([A-Za-z0-9_]{4,32})")
JABBER_RE = re.compile(r"[A-Za-z0-9._\-]+@(?:exploit\.im|jabber\.[A-Za-z]+|xmpp\.[A-Za-z]+|404\.city|thesecure\.biz)")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HWID_RE = re.compile(r"\bHWID[:\s]+([A-Fa-f0-9\-]{8,})", re.I)
RANDEXE_RE = re.compile(r"\b([A-Za-z]*\d[A-Za-z\d]{6,}\.exe)\b")  # random-looking dropped exe

# Signals that an infected machine belongs to a THREAT ACTOR, not a victim.
INFRA_KEYWORDS = {
    "underground": ["exploit.in", "xss.is", "lolz.", "zelenka.guru", "bhf.i", "cracked.",
                     "nulled.", "breach", "telegram.org", "web.telegram", "t.me", "jabber"],
    "crypto": ["binance", "okx.", "bybit", "coinbase", "kucoin", "blockchain.com", "metamask",
               "trustwallet", "kraken", "huobi", "mexc", "bitget", "blockchair", "tronscan", "etherscan"],
    "fraud_id": ["cek ktp", "ktp", "kartu keluarga", "dukcapil", "npwp", "pinjaman", "otp",
                 "kredit", "finance", "dana", "shopeepay", "ovo", "gopay"],
    "panel": ["admin.", "/admin", "backend", "/panel", "/cms", "dashboard", "/manage", "back office",
              "agent", "member.", "/bo/", "supplier", "merchant"],
    "disposable_mail": ["acidicmail", "guerrillamail", "temp-mail", "mailinator", "tempmail",
                        "10minutemail", "dropmail", "moakt"],
}

FAMILY_SIGNATURES = [
    # (regex over banner/info text, family label)
    (re.compile(r"stealc\s+stealer|powerful native stealer", re.I), "StealC"),
    (re.compile(r"vidar\s+stealer|vidars?\.su", re.I), "Vidar"),
    (re.compile(r"redline|redline_market_bot", re.I), "RedLine"),
    (re.compile(r"lumma|lummac2", re.I), "LummaC2"),
    (re.compile(r"raccoon", re.I), "Raccoon"),
    (re.compile(r"risepro", re.I), "RisePro"),
    (re.compile(r"meta\s*stealer|@BradMax", re.I), "RedLine/META (reseller)"),
]


def read_text(path):
    for enc in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            with open(path, "r", encoding=enc, errors="replace") as f:
                return f.read()
        except (OSError, UnicodeError):
            continue
    return ""


def walk_files(root):
    out = []
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            out.append(os.path.join(dp, f))
    return out


def find(files, *names):
    """Return files whose basename matches any of the lowercase name fragments."""
    hits = []
    for p in files:
        b = os.path.basename(p).lower()
        if any(n in b for n in names):
            hits.append(p)
    return hits


# ── per-artifact parsers ────────────────────────────────────────────────────
def parse_passwords(files):
    """Handle RedLine (URL/Username/Password/Application), StealC/Vidar
    (browser/profile/url/login/password) and Soft/Host/Login/Password blocks."""
    pw_files = [p for p in files if re.search(r"passwords?(_| |\.|bruteforce|tsv)?", os.path.basename(p).lower())
                and os.path.basename(p).lower().endswith((".txt", ".tsv"))
                and "unique" not in os.path.basename(p).lower()]
    recs = []
    keymap = {"url": "url", "host": "url", "soft": "app", "application": "app", "browser": "browser",
              "profile": "profile", "login": "login", "username": "login", "user": "login",
              "password": "password", "pass": "password"}
    for p in pw_files:
        txt = read_text(p)
        blocks = re.split(r"\n\s*\n|={5,}|-{5,}", txt)
        for blk in blocks:
            rec = {}
            for line in blk.splitlines():
                m = re.match(r"\s*([A-Za-z _]{3,12})\s*[:=]\s*(.+)$", line)
                if not m:
                    continue
                k = m.group(1).strip().lower()
                if k in keymap:
                    rec[keymap[k]] = m.group(2).strip()
            if rec.get("url") and (rec.get("login") or rec.get("password")):
                recs.append(rec)
    return recs


def parse_autofill(files):
    af = [p for p in files if "autofill" in p.lower()]
    pairs, emails, phones = [], set(), set()
    for p in af:
        txt = read_text(p)
        for line in txt.splitlines():
            line = line.strip()
            if not line:
                continue
            if ": " in line and not line.lower().startswith("http"):
                k, v = line.split(": ", 1)
            elif " " in line:
                k, v = line.split(" ", 1)
            else:
                continue
            k, v = k.strip(), v.strip()
            if v:
                pairs.append((k, v))
            for e in EMAIL_RE.findall(line):
                emails.add(e.lower())
            for ph in re.findall(r"\b(?:\+?\d[\d\-\s]{7,15}\d)\b", v):
                if len(re.sub(r"\D", "", ph)) >= 8:
                    phones.add(ph.strip())
    return pairs, sorted(emails), sorted(phones)


def parse_history(files):
    hist = [p for p in files if "history" in p.lower() or "history" in os.path.dirname(p).lower()]
    urls = []
    for p in hist:
        for u in URL_RE.findall(read_text(p)):
            urls.append(u.strip().rstrip(","))
    return urls


def parse_cookies(files):
    ck = [p for p in files if "cookie" in p.lower()]
    domains = Counter()
    total = 0
    for p in ck:
        for line in read_text(p).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = None
            if "\t" in line:
                host = line.split("\t", 1)[0]
            elif line.startswith("."):
                host = line.split()[0]
            if host and re.search(r"[A-Za-z]\.[A-Za-z]", host):
                domains[host.lstrip(".").lower()] += 1
                total += 1
    return domains, total


def domain_of(url):
    m = re.search(r"https?://([^/]+)", url, re.I)
    host = (m.group(1) if m else url).lower()
    return re.sub(r"^www\.", "", host.split("/")[0])


# ── Admin / sensitive-endpoint detection (subdomain prefix OR path segment) ──
# Strong indicators are matched by PREFIX (so admin→admin11, kef→kefu, adm→adm1n
# all hit); ambiguous ones require an exact label/segment to limit false hits.
ADMIN_STARTSWITH = ("admin", "adm", "adminer", "superadmin", "webadmin", "siteadmin",
                    "cpanel", "phpmyadmin", "backoffice", "backstage", "houtai",
                    "kef", "kefu", "ador", "wpadmin", "glht", "sysadmin")
ADMIN_EXACT = {"panel", "cp", "bo", "backend", "dashboard", "dash", "manage", "manager",
               "mgmt", "console", "control", "controlpanel", "master", "agent", "agents",
               "daili", "merchant", "seller", "cashier", "finance", "withdraw", "deposit",
               "recharge", "wallet", "gly", "boss", "operator", "staff", "pma",
               "jenkins", "grafana", "kibana", "portainer", "wp-admin", "wp-login",
               "administrator", "superuser", "root", "godmode"}
ADMIN_KW_RE = re.compile(r"(管理|后台|代理|客服|administrador)")


def classify_endpoint(url):
    """Detect admin panels / sensitive endpoints by subdomain prefix or path segment.

    High precision: only http(s) URLs; only admin-specific indicators (the noisy
    generic 'login/account/api' tier is intentionally excluded). Returns
    (is_admin, indicator, strong); indicator e.g. 'subdomain:kef', 'path:/admin',
    'subdomain:adm1n', 'keyword:cn-admin'.
    """
    if not url:
        return (False, "", False)
    s = url.strip()
    sm = re.match(r"([a-z][a-z0-9+.\-]*)://", s, re.I)
    if sm and sm.group(1).lower() not in ("http", "https"):
        return (False, "", False)  # ignore android:// / chrome-extension:// / etc.
    m = re.match(r"(?:https?://)?([^/?#]+)([/?#].*)?$", s, re.I)
    host = (m.group(1) if m else s).lower().split("@")[-1].split(":")[0]
    path = (m.group(2) or "") if m else ""
    labels = [x for x in host.split(".") if x]
    segs = [x for x in re.split(r"[/?#&=]", path) if x]

    for lab in labels:
        if any(lab.startswith(t) for t in ADMIN_STARTSWITH) or lab in ADMIN_EXACT:
            return (True, f"subdomain:{lab}", True)
    for seg in segs:
        sl = seg.lower()
        if any(sl.startswith(t) for t in ADMIN_STARTSWITH) or sl in ADMIN_EXACT:
            return (True, f"path:/{seg}", True)
    if ADMIN_KW_RE.search(s):
        return (True, "keyword:cn-admin", True)
    return (False, "", False)


# ── family / attribution ─────────────────────────────────────────────────────
def detect_family(info_text, files):
    for rx, label in FAMILY_SIGNATURES:
        if rx.search(info_text):
            return label
    low = info_text.lower()
    if "forza_traffic" in low or "ez_sources" in low:
        return "Traffer-branded (forza_traffic)"
    base = {os.path.basename(f).lower() for f in files}
    if "log_info.json" in base and "pc_info.json" in base:
        return "JSON-panel stealer (Lumma/StealC-family)"
    # Vidar variants often omit the ASCII banner — recognise its layout/fields.
    if re.search(r"\bMachineID\b", info_text) and re.search(r"\bWork Dir\b", info_text):
        return "Vidar"
    if "information.txt" in base and any("domain detect" in b for b in base) \
       and any("telegram" in f.lower() for f in files):
        return "Vidar"
    return "Unknown / generic"


def parse_info(files):
    """Pull the banner + host facts from the most info-like file(s)."""
    info_files = find(files, "system_info", "information.txt", "userinformation", "system.txt",
                      "environment", "copyright", "pc_info", "log_info", "info.txt")
    text = "\n".join(read_text(p) for p in info_files)
    g = {}

    def grab(pat):
        m = re.search(pat, text, re.I)
        return m.group(1).strip() if m else ""

    g["ip"] = grab(r"\bIP(?:\s*Address)?[:\s]+((?:\d{1,3}\.){3}\d{1,3})")
    g["country"] = grab(r"\bCountry[:\s]+([A-Za-z ]{2,30})")
    g["hwid"] = grab(r"\bHWID[:\s]+([A-Fa-f0-9\-]{8,})")
    g["machine"] = grab(r"(?:Computer Name|PcName|COMPUTERNAME|Hostname)[:=\s]+([^\n]+)")
    g["user"] = grab(r"(?:User ?Name|USERNAME|User)[:=\s]+([^\n]+)")
    g["os"] = grab(r"(?:OS(?: Version)?|Windows|Operation System)[:\s]+([^\n]+)")
    g["build"] = grab(r"(?:Build ?ID|Build|LID)[:\s]+([^\n]+)")
    g["version"] = grab(r"\bVersion[:\s]+([0-9.]+)")
    g["date"] = grab(r"(?:Log date|Date|Generated|Local Date|Local Time)[:\s]+([0-9/.\-: ]{8,})")
    # dropper / injection indicators
    paths = re.findall(r"(?:Path|FileLocation|Running Path)[:\s]+([^\n]+)", text, re.I)
    g["paths"] = [p.strip() for p in paths]
    procs = RANDEXE_RE.findall(text)
    g["susp_procs"] = sorted({p for p in procs if not p.lower().startswith(
        ("svchost", "runtime", "chrome", "msedge", "firefox"))})
    return g, text, info_files


def extract_contacts(text):
    tg = sorted(set(TME_RE.findall(text)))
    tg = [t for t in tg if t.lower() not in ("channel", "support", "telegram")]
    jabber = sorted(set(JABBER_RE.findall(text)))
    urls = sorted({u.rstrip("'\".,)") for u in URL_RE.findall(text)})
    panels = [u for u in urls if not re.search(r"(microsoft|google|mozilla|gstatic|w3\.org|schemas)", u, re.I)]
    return {"telegram": tg, "jabber": jabber, "panel_urls": panels}


# ── profiling ────────────────────────────────────────────────────────────────
MAIN_DOMAINS = ("google", "facebook", "netflix", "steam", "discord", "microsoft", "apple",
                "instagram", "tiktok", "youtube", "amazon", "epicgames", "live.com", "yahoo",
                "gmail", "roblox", "spotify", "paypal", "twitch")
SCAM_TLD_RE = re.compile(r"\.(xyz|top|vip|online|club|cc|icu|shop|fun|sbs|lol)(?:[:/]|$)", re.I)


def profile(passwords, autofill_pairs, emails, history_urls, cookie_domains):
    hay = " ".join([
        " ".join(f"{r.get('url','')} {r.get('login','')}" for r in passwords),
        " ".join(f"{k} {v}" for k, v in autofill_pairs),
        " ".join(history_urls),
        " ".join(cookie_domains.keys()),
    ]).lower()
    hits = defaultdict(list)
    for cat, kws in INFRA_KEYWORDS.items():
        for kw in kws:
            if kw in hay:
                hits[cat].append(kw)

    # Panel/back-office logins by keyword, by scam TLD, or by the multi-agent pattern
    # (>=3 distinct accounts on one non-mainstream domain = reseller/agent panel).
    by_domain = defaultdict(set)
    for r in passwords:
        u = r.get("url", "")
        if not u.lower().startswith(("http://", "https://")):
            continue  # skip android:// app deep-links etc.
        d = domain_of(u)
        if d and not any(m in d for m in MAIN_DOMAINS):
            by_domain[d].add(r.get("login", ""))
    multi_acct = {d for d, ls in by_domain.items() if len(ls) >= 3}

    def endpoint_flag(r):
        u = r.get("url", "")
        ok, ind, _strong = classify_endpoint(u)
        if ok:
            return ind
        if not u.lower().startswith(("http://", "https://")):
            return ""
        if SCAM_TLD_RE.search(u):
            return "scam-tld"
        if domain_of(u) in multi_acct:
            return "multi-agent-domain"
        return ""

    infra_logins = []
    for r in passwords:
        ind = endpoint_flag(r)
        if ind:
            rr = dict(r)
            rr["_ind"] = ind
            infra_logins.append(rr)
    if multi_acct:
        hits["agent_panels"] = sorted(multi_acct)[:20]

    score = (len(hits["underground"]) * 3 + len(hits["fraud_id"]) * 2 + len(hits["disposable_mail"]) * 2
             + len(hits["crypto"]) + len(infra_logins) + 2 * len(multi_acct)
             + (2 if len(emails) >= 5 else 0))
    if score >= 6:
        verdict = "OPERATOR / fraud-infrastructure machine (HIGH attribution value)"
    elif score >= 3:
        verdict = "MULE or mixed-use machine (notable attribution value)"
    else:
        verdict = "Likely VICTIM (low operator signal)"
    return verdict, score, dict(hits), infra_logins


# ── report ───────────────────────────────────────────────────────────────────
def analyze_log(folder):
    files = walk_files(folder)
    info, info_text, _ = parse_info(files)
    family = detect_family(info_text, files)
    contacts = extract_contacts(info_text)
    passwords = parse_passwords(files)
    af_pairs, emails, phones = parse_autofill(files)
    history = parse_history(files)
    cookies, cookie_total = parse_cookies(files)
    verdict, score, hits, admin_logins = profile(passwords, af_pairs, emails, history, cookies)
    # admin/sensitive endpoints that were *browsed* (in history) even without creds
    admin_browsed = {}
    for u in history:
        ok, ind, strong = classify_endpoint(u)
        if ok and strong and u not in admin_browsed:
            admin_browsed[u] = ind
    has = lambda *n: bool(find(files, *n))
    return {
        "log": os.path.basename(folder), "family": family, "host": info,
        "contacts": contacts, "verdict": verdict, "score": score, "signals": hits,
        "passwords": passwords, "admin_logins": admin_logins,
        "admin_browsed": admin_browsed,
        "autofill": af_pairs, "emails": emails, "phones": phones,
        "history_domains": Counter(domain_of(u) for u in history),
        "cookie_domains": cookies, "cookie_total": cookie_total,
        "has_wallets": has("wallet"), "has_discord": has("discord", "token"),
        "has_telegram": has("tdata"), "file_count": len(files),
    }


def md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def cap(seq, n=300):
    seq = list(seq)
    return seq[:n], (len(seq) - n if len(seq) > n else 0)


def build_report(root, logs):
    L = []
    today = datetime.date.today().isoformat()
    L.append(f"# Stealer-Log CTI Analysis — `{os.path.basename(root.rstrip('/\\'))}`")
    L.append(f"\n_Generated {today} · {len(logs)} logs · "
             f"{sum(l['file_count'] for l in logs)} files._\n")
    L.append("> Contains third-party PII recovered from infostealer logs. Use only for "
             "authorized CTI/attribution and victim-notification; handle per your data-protection duties.\n")

    # cross-log attribution + IOC rollup
    fams = Counter(l["family"] for l in logs)
    tg = Counter(); jab = Counter(); panels = Counter(); actor_emails = Counter()
    scam_domains = Counter(); victim_ips = []; hwids = []; susp = Counter()
    admin_eps = {}   # url -> [indicator, set(logs)]
    for l in logs:
        for t in l["contacts"]["telegram"]:
            tg[t] += 1
        for j in l["contacts"]["jabber"]:
            jab[j] += 1
        for u in l["contacts"]["panel_urls"]:
            panels[u] += 1
        for r in l["admin_logins"]:
            scam_domains[domain_of(r.get("url", ""))] += 1
            admin_eps.setdefault(r.get("url", ""), [r.get("_ind", ""), set()])[1].add(l["log"])
        for u, ind in l.get("admin_browsed", {}).items():
            admin_eps.setdefault(u, [ind, set()])[1].add(l["log"])
        for e in l["emails"]:
            actor_emails[e] += 1
        if l["host"].get("ip"):
            victim_ips.append((l["host"]["ip"], l["host"].get("country", "")))
        if l["host"].get("hwid"):
            hwids.append(l["host"]["hwid"])
        for sp in l["host"].get("susp_procs", []):
            susp[sp] += 1

    L.append("## 1. Attribution summary\n")
    L.append("| Stealer family | Logs |\n|---|---|")
    for f, c in fams.most_common():
        L.append(f"| {md_escape(f)} | {c} |")
    L.append("\n**Seller / traffer contacts (attribution):**")
    for t, c in tg.most_common():
        L.append(f"- Telegram `@{t}` ({c})")
    for j, c in jab.most_common():
        L.append(f"- Jabber `{j}` ({c})")
    if not tg and not jab:
        L.append("- (none recovered)")

    # ── cross-log actor correlation ──
    links = defaultdict(set)
    for l in logs:
        keys = set()
        for sp in l["host"].get("susp_procs", []):
            keys.add(("dropper exe", sp.lower()))
        for p in l["host"].get("paths", []):
            b = os.path.basename(p).lower()
            if b and b not in ("explorer.exe",):
                keys.add(("dropper path", b))
        if l["host"].get("hwid"):
            keys.add(("HWID", l["host"]["hwid"][:20]))
        for e in l["emails"][:40]:
            keys.add(("email", e))
        for k in keys:
            links[k].add(l["log"])
    shared = {k: frozenset(v) for k, v in links.items() if len(v) > 1}
    L.append("\n## 2. Cross-log actor correlation\n")
    if shared:
        # union logs that share any artifact into operator clusters
        parent = {l["log"]: l["log"] for l in logs}

        def root(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for grp in shared.values():
            g = sorted(grp)
            for o in g[1:]:
                parent[root(o)] = root(g[0])
        clusters = defaultdict(list)
        for name in parent:
            clusters[root(name)].append(name)
        clusters = [c for c in clusters.values() if len(c) > 1]

        L.append("Logs sharing identity/dropper artifacts — likely the **same operator**:\n")
        for i, c in enumerate(clusters, 1):
            cset = set(c)
            arts = defaultdict(list)
            for (kind, val), names in shared.items():
                if set(names) <= cset:
                    arts[kind].append(val)
            L.append(f"**Cluster {chr(64+i)}** — {len(c)} logs: {', '.join('`'+n+'`' for n in c)}")
            for kind in ("dropper exe", "dropper path", "HWID", "email"):
                if arts.get(kind):
                    vals, more = cap(sorted(set(arts[kind])), 12)
                    extra = f" _+{more} more_" if more else ""
                    L.append(f"  - shared {kind}: " + ", ".join(f"`{md_escape(v)}`" for v in vals) + extra)
            L.append("")
    else:
        L.append("_No shared identity/dropper artifacts across logs._")

    L.append("\n## 3. IOCs\n")
    L.append("**Operator panel / C2 / forum URLs (from banners):**")
    for u, c in panels.most_common(40):
        L.append(f"- `{u}`")
    L.append("\n**Scam / admin-panel domains (from actors' own logins — high-value IOCs):**")
    for d, c in scam_domains.most_common(60):
        L.append(f"- `{d}` ({c} admin login(s))")
    if not scam_domains:
        L.append("- (none)")

    L.append("\n**Admin / sensitive endpoints — subdomain-prefix or path (all logs):**")
    eps = sorted(admin_eps.items(), key=lambda kv: (-len(kv[1][1]), kv[0]))
    for url, (ind, lgs) in eps[:80]:
        L.append(f"- `{md_escape(url)}`  [{md_escape(ind)}]")
    if len(eps) > 80:
        L.append(f"- _+{len(eps)-80} more endpoints (see JSON)_")
    if not eps:
        L.append("- (none)")
    L.append("\n**Suspected dropper processes / paths:**")
    for s, c in susp.most_common(20):
        L.append(f"- `{s}`")
    for l in logs:
        for p in l["host"].get("paths", []):
            if re.search(r"syswow32|install\.exe|regasm|appdata\\local\\temp|programdata", p, re.I):
                L.append(f"- `{md_escape(p)}`  ({l['log']})")
    L.append("\n**Compromised-host IPs (victim/infection telemetry):**")
    for ip, cc in victim_ips:
        L.append(f"- `{ip}` ({cc})")

    # per-log profiles
    L.append("\n## 4. Per-log profiles & raw evidence\n")
    for l in logs:
        h = l["host"]
        L.append(f"\n### {md_escape(l['log'])}")
        L.append(f"- **Family:** {md_escape(l['family'])}"
                 + (f" · build `{md_escape(h.get('build'))}`" if h.get("build") else "")
                 + (f" · v{md_escape(h.get('version'))}" if h.get("version") else ""))
        L.append(f"- **Verdict:** **{l['verdict']}** (signal score {l['score']})")
        sig = "; ".join(f"{k}: {', '.join(sorted(set(v)))}" for k, v in l["signals"].items() if v)
        if sig:
            L.append(f"- **Profiling signals:** {md_escape(sig)}")
        L.append(f"- **Host:** IP `{h.get('ip','?')}` ({h.get('country','?')}) · "
                 f"machine `{md_escape(h.get('machine','?'))}` · user `{md_escape(h.get('user','?'))}` · "
                 f"OS {md_escape(h.get('os','?'))} · HWID `{h.get('hwid','?')}`")
        present = [n for n, v in [("Telegram tdata", l["has_telegram"]),
                   ("Discord tokens", l["has_discord"]), ("crypto wallets", l["has_wallets"])] if v]
        if present:
            L.append(f"- **Sensitive artifacts present:** {', '.join(present)}")

        if l["admin_logins"]:
            L.append(f"\n**🚩 Admin / panel / agent logins ({len(l['admin_logins'])}) — actor infrastructure:**\n")
            L.append("| URL | Login | Password | Indicator |\n|---|---|---|---|")
            rows, more = cap(l["admin_logins"], 100)
            for r in rows:
                L.append(f"| {md_escape(r.get('url',''))} | {md_escape(r.get('login',''))} | "
                         f"{md_escape(r.get('password',''))} | `{md_escape(r.get('_ind',''))}` |")
            if more:
                L.append(f"| _+{more} more_ | | | |")

        if l.get("admin_browsed"):
            L.append(f"\n**Admin/sensitive endpoints browsed (history, no creds) — {len(l['admin_browsed'])}:**")
            for u, ind in list(l["admin_browsed"].items())[:40]:
                L.append(f"- `{md_escape(u)}`  [{md_escape(ind)}]")

        if l["passwords"]:
            L.append(f"\n**All recovered credentials ({len(l['passwords'])}):**\n")
            L.append("| URL | Login | Password |\n|---|---|---|")
            rows, more = cap(l["passwords"], 300)
            for r in rows:
                L.append(f"| {md_escape(r.get('url',''))} | {md_escape(r.get('login',''))} | {md_escape(r.get('password',''))} |")
            if more:
                L.append(f"| _+{more} more credentials_ | | |")

        if l["emails"]:
            L.append(f"\n**Identity — emails from autofill ({len(l['emails'])}):** "
                     + ", ".join(f"`{e}`" for e in l["emails"][:60]))
        if l["phones"]:
            L.append(f"\n**Phones:** " + ", ".join(f"`{p}`" for p in l["phones"][:40]))
        notable_af = [(k, v) for k, v in l["autofill"]
                      if re.search(r"name|address|phone|nik|ktp|card|note|company|user|account|wallet|id", k, re.I)][:40]
        if notable_af:
            L.append(f"\n**Notable autofill fields:**")
            for k, v in notable_af:
                L.append(f"- `{md_escape(k)}` = {md_escape(v)}")

        if l["history_domains"]:
            L.append(f"\n**Top browsing domains ({sum(l['history_domains'].values())} URLs):** "
                     + ", ".join(f"`{d}` ({c})" for d, c in l["history_domains"].most_common(25)))
        if l["cookie_domains"]:
            L.append(f"\n**Active cookie/session domains (top 25 of {len(l['cookie_domains'])}):** "
                     + ", ".join(f"`{d}`" for d, _ in l["cookie_domains"].most_common(25)))
    return "\n".join(L)


def main():
    if len(sys.argv) < 2:
        print("Usage: stealer_log_parse.py <log-folder> [out-dir]")
        sys.exit(1)
    root = os.path.abspath(sys.argv[1])
    out_dir = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.getcwd()
    if not os.path.isdir(root):
        print(f"Not a folder: {root}")
        sys.exit(1)

    subdirs = [os.path.join(root, d) for d in os.listdir(root)
               if os.path.isdir(os.path.join(root, d))]
    # A subdir is a "log" if it holds stealer artifacts; else treat root as one log.
    def is_log(d):
        return bool(find(walk_files(d), "password", "system_info", "information",
                         "userinformation", "system.txt", "cookie", "autofill", "pc_info"))
    targets = [d for d in subdirs if is_log(d)] or [root]

    print(f"Analyzing {len(targets)} log folder(s) under {root} ...")
    logs = []
    for d in sorted(targets):
        try:
            logs.append(analyze_log(d))
            print(f"  + {os.path.basename(d)}: {logs[-1]['family']} | {logs[-1]['verdict']}")
        except Exception as e:  # never let one bad log abort the batch
            print(f"  ! {os.path.basename(d)}: skipped ({e})")

    report = build_report(root, logs)
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.date.today().isoformat()
    md_path = os.path.join(out_dir, f"STEALER-ANALYSIS-{stamp}.md")
    json_path = os.path.join(out_dir, f"STEALER-ANALYSIS-{stamp}.json")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([{k: (dict(v) if isinstance(v, Counter) else v) for k, v in l.items()} for l in logs],
                  f, ensure_ascii=False, indent=2, default=str)
    print(f"\nSaved:\n  {md_path}\n  {json_path}")


if __name__ == "__main__":
    main()
