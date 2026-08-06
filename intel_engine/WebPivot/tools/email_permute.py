#!/usr/bin/env python3
"""email_permute.py — deterministic email CANDIDATE generation from a person name or a username.

WHAT THIS IS FOR
----------------
You have a name ("Nguyen Van Hieu") or a handle ("jdoe") and a domain that matters to the case.
The operator's mailbox is almost never published, but it is almost always *derivable*: corporate
and hosted mail overwhelmingly uses a handful of local-part conventions. This enumerates them.

WHAT THIS IS NOT
----------------
A finding generator. Permutation is CHEAP and therefore NOISY: 40 patterns x 6 free-mail providers
is 240 fabricated addresses, none of which any evidence supports. So this tool is built around one
invariant, and every output field exists to enforce it:

    A permuted address is a HYPOTHESIS (status="candidate"). It is NEVER an indicator, NEVER a
    KB fact, and NEVER a new seed for the spider-map -- until something INDEPENDENT corroborates
    it, at which point it is promoted to status="corroborated" and listed under "promote".

That is not conservatism for its own sake. A fabricated address ingested into the knowledge base
becomes a shared indicator, and a shared indicator merges two operator clusters. A permutator wired
straight into correlation does not enrich a case; it silently names innocent people.

NOISE CONTROL -- the domain set is the whole game
------------------------------------------------
By DEFAULT this permutes only against domains you pass in (i.e. domains already in the case).
Name x the operator's own domain is a high-yield, low-volume question. Name x gmail.com is volume
with no prior. `--free` opts into the free-mail providers and is capped, deliberately.

Domains with no MX cannot receive mail, so every candidate under them is dead on arrival --
`--verify` drops them wholesale before a single per-address check runs. That one DNS lookup is the
cheapest noise reduction available.

VERIFICATION -- what we will and will not do
--------------------------------------------
  MX check (DNS-over-HTTPS)  domain-level gate. Keyless. Touches a public resolver, not the target.
  Gravatar existence         md5(address) -> gravatar.com/avatar/<hash>?d=404. A 200 means that
                             exact address is registered with Gravatar: real existence evidence,
                             obtained from Gravatar, never from the target's mail server.

  SMTP RCPT TO probing       REFUSED, and not as an oversight:
                             (1) it connects to the TARGET's mail infrastructure -- the egress gate
                                 exists precisely to stop that on a hostile case;
                             (2) a catch-all domain answers 250 for every address ever tried, so it
                                 manufactures confidence rather than measuring it;
                             (3) it is the classic precursor signature of address harvesting.
                             A validator that lies is worse than no validator.

LOCALE
------
Generic permutators mangle Vietnamese names two ways, and both are silent:
  * `d` with stroke (U+0111) has NO Unicode decomposition, so NFKD folding leaves it intact and
    every generated address is wrong. It is folded explicitly here, with the other non-decomposing
    Latin letters (l-stroke, o-slash, ae, oe, sharp-s, thorn, eth, dotless-i).
  * Vietnamese, Chinese and Korean names are FAMILY-NAME-FIRST. Read left-to-right, the surname is
    taken as the given name and first.last is inverted. Auto-detected from a surname table; force
    it either way with --order.

Usage:
  uv run email_permute.py "Nguyen Van Hieu" --domain example.com
  uv run email_permute.py "First Last" --domain site-a.example --domain site-b.example --verify
  uv run email_permute.py jdoe --username --domain example.com
  uv run email_permute.py "First Last" --free --max 40 --pretty
  uv run email_permute.py "First Last" --domain example.com --verify -o candidates.json
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

import argparse
import hashlib
import json
import re
import unicodedata
import urllib.error
import urllib.request

TIMEOUT = 8

# ─────────────────────────────────────────────────────────────────────────────
# Folding
#
# NFKD decomposes accents, but a handful of Latin letters are ATOMIC codepoints with no
# decomposition -- they survive folding unchanged and silently corrupt every address built from
# them. Vietnamese d-stroke is the one that matters most here.
# ─────────────────────────────────────────────────────────────────────────────
ATOMIC_FOLD = {
    "đ": "d", "Đ": "D",      # đ Đ  Vietnamese / Croatian d-stroke
    "ł": "l", "Ł": "L",      # ł Ł  Polish l-stroke
    "ø": "o", "Ø": "O",      # ø Ø  Nordic o-slash
    "æ": "ae", "Æ": "AE",    # æ Æ
    "œ": "oe", "Œ": "OE",    # œ Œ
    "ß": "ss",                    # ß    German sharp s
    "þ": "th", "Þ": "TH",    # þ Þ  thorn
    "ð": "d", "Ð": "D",      # ð Ð  eth
    "ı": "i", "İ": "I",      # ı İ  Turkish dotless/dotted i
}


def fold(text):
    """Unicode -> bare ASCII lowercase, safe for an email local part."""
    if not text:
        return ""
    out = "".join(ATOMIC_FOLD.get(ch, ch) for ch in text)
    out = unicodedata.normalize("NFKD", out)
    out = "".join(ch for ch in out if not unicodedata.combining(ch))
    out = out.lower()
    return re.sub(r"[^a-z0-9]", "", out)


# Family-name-first surnames. Presence of token[0] in this set flips the parse.
# Folded ASCII, so "Nguyễn" and "Nguyen" both hit.
FAMILY_FIRST_SURNAMES = {
    # Vietnamese
    "nguyen", "tran", "le", "pham", "hoang", "huynh", "phan", "vu", "vo", "dang", "bui", "do",
    "ho", "ngo", "duong", "ly", "dao", "doan", "truong", "dinh", "lam", "mai", "trinh", "ha",
    "luong", "tang", "cao", "chu", "thai", "kieu", "quach", "ta", "ton", "vuong",
    # Chinese (Mandarin/Cantonese romanisations)
    "wang", "li", "zhang", "liu", "chen", "yang", "huang", "zhao", "wu", "zhou", "xu", "sun",
    "ma", "zhu", "hu", "guo", "he", "gao", "lin", "luo", "zheng", "liang", "xie", "song", "tang",
    "deng", "han", "feng", "zeng", "peng", "xiao", "tian", "dong", "yuan", "pan", "yu", "jiang",
    "cai", "yao", "shen", "chan", "cheung", "lau", "wong", "leung", "ng", "chow", "yip", "tsang",
    # Korean
    "kim", "lee", "park", "choi", "jung", "jeong", "kang", "cho", "yoon", "jang", "lim", "oh",
    "seo", "shin", "kwon", "hwang", "ahn", "yoo", "hong", "moon", "son", "bae", "baek", "nam",
}

# Common one-token generational/middle particles that are never the given name.
VN_MIDDLE_PARTICLES = {"van", "thi", "duc", "minh", "ngoc", "huu", "quang", "xuan", "hong", "anh"}

FREE_MAIL = [
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "icloud.com",
]

# ─────────────────────────────────────────────────────────────────────────────
# Pattern table
#
# `prior` = how often this convention appears in the wild, 0-100. It is a PRIOR on the pattern,
# NOT confidence in the address: a first.last candidate with prior 95 is still an unverified
# guess. Confidence only becomes non-zero when evidence corroborates it.
#
# Templates use: f=first, m=middle, l=last, and Fi/Mi/Li for single initials.
# ─────────────────────────────────────────────────────────────────────────────
PATTERNS = [
    ("first.last",        "{f}.{l}",        95),
    ("flast",             "{Fi}{l}",        85),
    ("first",             "{f}",            80),
    ("firstlast",         "{f}{l}",         72),
    ("first_last",        "{f}_{l}",        64),
    ("f.last",            "{Fi}.{l}",       62),
    ("firstl",            "{f}{Li}",        56),
    ("last",              "{l}",            50),
    ("first-last",        "{f}-{l}",        44),
    ("last.first",        "{l}.{f}",        40),
    ("lastfirst",         "{l}{f}",         34),
    ("first.l",           "{f}.{Li}",       32),
    ("lastf",             "{l}{Fi}",        26),
    ("last_first",        "{l}_{f}",        24),
    ("l.first",           "{Li}.{f}",       20),
    ("lfirst",            "{Li}{f}",        18),
    ("initials",          "{Fi}{Li}",       16),
    # middle-name forms — only emitted when a middle name is present
    ("first.middle.last", "{f}.{m}.{l}",    30),
    ("firstmlast",        "{f}{Mi}{l}",     22),
    ("f.m.last",          "{Fi}.{Mi}.{l}",  14),
    ("firstmiddlelast",   "{f}{m}{l}",      12),
]

MIDDLE_PATTERNS = {"first.middle.last", "firstmlast", "f.m.last", "firstmiddlelast"}


def parse_name(raw, order="auto"):
    """Split a display name into folded first / middle / last, honouring name order.

    Returns (first, middle, last, resolved_order, tokens).
    """
    tokens = [t for t in re.split(r"[\s,]+", (raw or "").strip()) if t]
    folded = [fold(t) for t in tokens]
    folded = [t for t in folded if t]
    if not folded:
        return "", "", "", order, []

    if len(folded) == 1:
        return folded[0], "", "", "single", folded

    resolved = order
    if order == "auto":
        resolved = "family-first" if folded[0] in FAMILY_FIRST_SURNAMES else "given-first"

    if resolved == "family-first":
        # Surname Middle... Given   ->   the LAST token is the given name.
        last = folded[0]
        first = folded[-1]
        middle_parts = folded[1:-1]
    else:
        first = folded[0]
        last = folded[-1]
        middle_parts = folded[1:-1]

    # Drop pure generational particles from the middle — they are never used in an address.
    middle_parts = [m for m in middle_parts if m not in VN_MIDDLE_PARTICLES] or middle_parts
    middle = middle_parts[0] if middle_parts else ""
    return first, middle, last, resolved, folded


def local_parts(first, middle, last, username=None):
    """Yield (pattern_name, local_part, prior), highest prior first, de-duplicated."""
    out, seen = [], set()

    if username:
        u = fold(username)
        if u:
            out.append(("username", u, 90))
            seen.add(u)
        # A handle carrying a separator often IS first+last; low prior, but free to try.
        parts = [p for p in re.split(r"[._\-]+", (username or "").lower()) if p]
        if len(parts) == 2 and not (first or last):
            first, last = fold(parts[0]), fold(parts[1])

    if not (first or last):
        return out

    ctx = {
        "f": first, "m": middle, "l": last,
        "Fi": first[:1], "Mi": middle[:1], "Li": last[:1],
    }
    for name, tpl, prior in PATTERNS:
        if name in MIDDLE_PATTERNS and not middle:
            continue
        if "{l}" in tpl and not last:
            continue
        if "{f}" in tpl and not first:
            continue
        lp = tpl.format(**ctx)
        lp = re.sub(r"[._\-]{2,}", ".", lp).strip("._-")
        if not lp or lp in seen:
            continue
        seen.add(lp)
        out.append((name, lp, prior))

    out.sort(key=lambda r: (-r[2], r[0]))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Verification — keyless, and never against the target's mail server
# ─────────────────────────────────────────────────────────────────────────────
def _get(url, expect_json=False):
    req = urllib.request.Request(url, headers={"User-Agent": "cti-expert/email_permute"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read()
            return r.status, (json.loads(body.decode("utf-8", "replace")) if expect_json else body)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def is_null_mx(rdata):
    """RFC 7505 null MX — `0 .` — is an EXPLICIT declaration that the domain accepts no mail.

    It is a present MX record, so a naive truthiness test reads it as "mail works" and lets every
    candidate under that domain through. It means the exact opposite of that.
    """
    exchange = (rdata or "").strip().split()[-1] if (rdata or "").strip() else ""
    return exchange in (".", "")


def has_mx(domain):
    """True / False / None(unknown) — via DNS-over-HTTPS, keyless."""
    for base in ("https://dns.google/resolve?name={}&type=MX",
                 "https://cloudflare-dns.com/dns-query?name={}&type=MX"):
        status, data = _get(base.format(domain), expect_json=True)
        if status == 200 and isinstance(data, dict):
            answers = data.get("Answer") or []
            mx = [a for a in answers
                  if a.get("type") == 15 and not is_null_mx(a.get("data"))]
            return bool(mx)
    return None


def gravatar_exists(email):
    """True if this exact address is registered with Gravatar. Contacts Gravatar, not the target."""
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    status, _ = _get("https://www.gravatar.com/avatar/{}?d=404&s=1".format(h))
    if status == 200:
        return True
    if status == 404:
        return False
    return None


POLICY = {
    "candidates_are_hypotheses": True,
    "auto_ingest_to_kb": False,
    "auto_seed_spider_map": False,
    "smtp_rcpt_probing": "refused — contacts the target's mail server, and catch-all domains "
                         "answer 250 for every address, so it fabricates confidence",
    "promotion_rule": "a candidate becomes a usable email seed only when independent evidence "
                      "(Gravatar registration, breach corpus, GitHub commit, page/DOM, dork hit) "
                      "confirms it — see the 'promote' list",
}


def permute(name=None, username=None, domains=None, order="auto", free=False,
            max_candidates=60, verify=False):
    domains = list(domains or [])
    if free:
        domains.extend(d for d in FREE_MAIL if d not in domains)
    domains = [d.strip().lower().lstrip("@") for d in domains if d and d.strip()]

    first, middle, last, resolved, tokens = ("", "", "", order, [])
    if name:
        first, middle, last, resolved, tokens = parse_name(name, order)

    parts = local_parts(first, middle, last, username=username)

    domain_rows = []
    for d in domains:
        row = {"domain": d, "mx": None}
        if verify:
            row["mx"] = has_mx(d)
        domain_rows.append(row)

    candidates = []
    for d in domain_rows:
        # No MX ⇒ the domain cannot receive mail ⇒ every candidate under it is dead.
        if verify and d["mx"] is False:
            continue
        for pattern, lp, prior in parts:
            candidates.append({
                "email": "{}@{}".format(lp, d["domain"]),
                "local_part": lp,
                "domain": d["domain"],
                "pattern": pattern,
                "prior": prior,
                "status": "candidate",
                "confidence": 0,
                "evidence": [],
            })

    candidates.sort(key=lambda c: (-c["prior"], c["email"]))
    truncated = max(0, len(candidates) - max_candidates)
    candidates = candidates[:max_candidates]

    if verify:
        for c in candidates:
            hit = gravatar_exists(c["email"])
            if hit is True:
                c["status"] = "corroborated"
                c["confidence"] = 75
                c["evidence"].append({
                    "source": "gravatar",
                    "detail": "address is registered with Gravatar (avatar returns 200, not 404)",
                })

    return {
        "input": {"name": name, "username": username, "order_requested": order, "free": free},
        "parsed": {
            "first": first, "middle": middle, "last": last,
            "order_resolved": resolved, "tokens": tokens,
        },
        "domains": domain_rows,
        "patterns_used": len(parts),
        "candidates": candidates,
        "truncated": truncated,
        "promote": [c["email"] for c in candidates if c["status"] == "corroborated"],
        "policy": POLICY,
    }


def render(res):
    p, lines = res["parsed"], []
    lines.append("email_permute — CANDIDATES, not findings")
    who = res["input"].get("name") or res["input"].get("username") or "?"
    lines.append("  input      : {}".format(who))
    if p["first"] or p["last"]:
        lines.append("  parsed     : first={} middle={} last={}  (order: {})".format(
            p["first"] or "-", p["middle"] or "-", p["last"] or "-", p["order_resolved"]))
    doms = ", ".join("{}{}".format(
        d["domain"],
        "" if d["mx"] is None else (" [MX ok]" if d["mx"] else " [NO MX — dropped]"),
    ) for d in res["domains"]) or "(none — pass --domain or --free)"
    lines.append("  domains    : {}".format(doms))
    lines.append("  patterns   : {}".format(res["patterns_used"]))
    lines.append("")
    if not res["candidates"]:
        lines.append("  no candidates — supply at least one domain")
        return "\n".join(lines)
    lines.append("  {:<38} {:<18} {:>5}  {}".format("CANDIDATE", "PATTERN", "PRIOR", "STATUS"))
    for c in res["candidates"]:
        mark = "CORROBORATED" if c["status"] == "corroborated" else "candidate"
        lines.append("  {:<38} {:<18} {:>5}  {}".format(
            c["email"][:38], c["pattern"], c["prior"], mark))
    if res["truncated"]:
        lines.append("  … {} more suppressed by --max (raise it, or narrow the domain set)".format(
            res["truncated"]))
    lines.append("")
    if res["promote"]:
        lines.append("  PROMOTE ({} corroborated — safe to treat as an email seed):".format(
            len(res["promote"])))
        for e in res["promote"]:
            lines.append("    • {}".format(e))
    else:
        lines.append("  PROMOTE: none. Every row above is an unverified hypothesis — do NOT ingest")
        lines.append("  them into the KB, cite them in a report, or contact them.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Generate email CANDIDATES from a person name or username. "
                    "Output is hypotheses, never findings.")
    ap.add_argument("subject", help='person name ("Nguyen Van Hieu") or a username')
    ap.add_argument("--username", action="store_true",
                    help="treat the subject as a handle rather than a person name")
    ap.add_argument("--domain", action="append", default=[],
                    help="domain to permute against (repeatable). Default and best practice: "
                         "domains already in the case")
    ap.add_argument("--free", action="store_true",
                    help="also permute against common free-mail providers (high noise — opt-in)")
    ap.add_argument("--order", choices=["auto", "given-first", "family-first"], default="auto",
                    help="name order; auto-detects family-first VN/CN/KR surnames")
    ap.add_argument("--verify", action="store_true",
                    help="keyless corroboration: MX gate per domain + Gravatar existence per "
                         "address. Never probes the target's mail server")
    ap.add_argument("--max", type=int, default=60, dest="max_candidates",
                    help="cap on emitted candidates (default 60)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--pretty", action="store_true", help="pretty-print the JSON")
    ap.add_argument("-o", "--out", help="write JSON to this path")
    args = ap.parse_args()

    res = permute(
        name=None if args.username else args.subject,
        username=args.subject if args.username else None,
        domains=args.domain,
        order=args.order,
        free=args.free,
        max_candidates=args.max_candidates,
        verify=args.verify,
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2, ensure_ascii=False)
        print("wrote {}".format(args.out))
    if args.json or args.pretty:
        print(json.dumps(res, indent=2 if args.pretty else None, ensure_ascii=False))
    elif not args.out:
        print(render(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
