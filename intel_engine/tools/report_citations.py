#!/usr/bin/env python3
"""report_citations.py — IntelReport Rule 21 source citations, shared by the house report
(tools/house_report.py) and the per-round assessment snapshots (harness/render.py,
tools/case_store.py).

A claim is cited to a link a reader can re-open. Every public http(s) URL becomes a numbered,
hyperlinked `[n]` and a row in a References section. A loopback / private-address URL is internal
working (Rule 12) and is never cited. Vendor / tool names map to a public source CLASS (Rule 12)
while indicator values are never rewritten (Rule 12a).

The snapshot side adds three things the house report does not do:
  * `strip_secrets` — credential query/fragment keys (references/report_citations.json
    `secret_query_keys`) and URL user-info are removed from every URL, so an API key that leaked
    into an evidence string never reaches a snapshot, its JSON or its References.
  * `cite_claim` — a claim with no URL gets the public page that re-checks it, rebuilt from the
    claim (`source_links` rules: crt.sh, RDAP, urlscan, the web archive, the page itself …). A
    claim whose only source is a non-public vendor API is cited by its source class with
    "(no public link)" so it never silently looks uncited.
  * `finalize` — the scrub + citation pass + References for one markdown document.

Stdlib only. The snapshot entry points never raise: on any internal error they return their input.
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REF_PATH = os.path.join(ROOT, "IntelReport", "references", "report_citations.json")

for _p in (os.path.join(ROOT, "IntelReport", "scripts"), os.path.join(ROOT, "WebPivot", "tools")):
    if _p not in sys.path:
        sys.path.append(_p)   # APPEND: never shadow a caller's same-named module

_FALLBACK = {
    "secret_query_keys": ["key", "apikey", "api_key", "token", "access_token", "secret", "password",
                          "signature", "sig", "auth"],
    "source_links": {},
}
try:
    from ir_refs import load_ref  # noqa: E402
    _REF = load_ref(REF_PATH, _FALLBACK)
except Exception as _exc:  # noqa: BLE001 — degrade loudly, never break a render
    sys.stderr.write(f"[refs] WARNING: report_citations reference unavailable ({_exc!r}); "
                     f"using the embedded fallback.\n")
    _REF = dict(_FALLBACK)
SECRET_QUERY_KEYS = frozenset(str(k).lower() for k in _REF.get("secret_query_keys") or [])
SOURCE_LINKS = {k: v for k, v in (_REF.get("source_links") or {}).items()
                if isinstance(v, dict) and v.get("url") and v.get("match")}

try:  # eTLD+1 reducer and TLD check shared with the collectors (PSL-aware); degrade to last-two-labels
    from wp_common import _registrable as _registrable_apex, has_known_tld  # noqa: E402
except Exception:  # pragma: no cover
    def _registrable_apex(host):
        parts = (host or "").lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")

    def has_known_tld(host):
        return True


# --------------------------------------------------------------------------- Rule 12 vendor scrub
# Internal working / data-vendor names -> public source CLASS. Case evidence is never touched.
# _V(): a bare vendor word that must not rewrite an indicator VALUE (Rule 12a) — no match inside a
# host/e-mail label (`otx.example`, `ops-netlas.example`, `subfinder@example.com`).
def _V(word: str) -> str:
    return rf"(?<![\w.@-]){word}(?![\w@-]|\.[A-Za-z0-9])"


PUBLIC_CLASS = [
    (r"\bwhoisxmlapi\.com\b|\brdap\.org\b", "registration-data service"),
    (r"\bintelx\.io\b", "leak-corpus search"),
    (r"\bcrt\.sh\b", "certificate transparency"),
    (r"\bWhoisXML\b", "registration-data service"),
    (r"\bIntelX\b|\bIntelligence X\b", "leak-corpus search"),
    (r"\bCLD\b|\bChongLuaDao\b|\bChống Lừa Đảo\b", "anti-scam verdict service"),
    (r"\bHudsonRock(-class)?\b", "infostealer-corpus"),
    (r"\bFOFA\b|\burlscan(\.io)?\b|\bCensys\b|\bShodan\b|\bValidin\b|\bSecurityTrails\b|\bDNSLytics\b|\bQuake\b|\bZoomEye\b|\bHunter\.how\b|\bWebamon\b",
     "web-scan index"),
    (_V("Netlas"), "web-scan index"),
    (_V(r"(?:ANY\.RUN|AnyRun)"), "malware sandbox"),
    (_V("VirusTotal"), "multi-engine reputation service"),
    (_V("(?:Spamhaus|AbuseIPDB|OTX)"), "reputation feed"),
    (_V("HackerTarget"), "passive DNS"),
    (_V("CIRCL"), "passive DNS / certificate archive"),
    (_V("subfinder"), "subdomain enumeration"),
    (r"\bmaigret\b|\bsherlock\b", "username enumeration"),
    (r"\bWayback\b", "web-archive"),
    (r"\bCDX\b", "archive-index"),
    (r"\bIPinfo\b", "IP/ASN data"),
    (r"(?-i:\bMoli\b)", "headless renderer"),   # case-sensitive: `moli` is an ordinary word elsewhere
    (r"\bpivot_extract\b|\bpipeline open\b|\bcase-store\b|\bkb_ingest\b|\bintel\.py\b|\breference ledger\b|\boperators ledger\b|\bthe KB\b|\bknowledge base\b",
     "the case record"),
]
# "registration-data service lookup via registration-data service" -> one mention of the class
_DUP_CLASS_RES = [re.compile(rf"({re.escape(cls)})((?:\s+[\w-]+)?)\s+(?:via|from|at)\s+{re.escape(cls)}\b", re.I)
                  for cls in dict.fromkeys(c for _, c in PUBLIC_CLASS)]


def scrub_vendors(line: str) -> str:
    """Rule 12 vendor/tool names -> public source class; indicator values are never rewritten."""
    for pat, repl in PUBLIC_CLASS:
        line = re.sub(pat, repl, line, flags=re.I)
    for rx in _DUP_CLASS_RES:
        line = rx.sub(r"\1\2", line)
    return line


# --------------------------------------------------------------------------- evidence links
_URL_RE = re.compile(r"https?://[^\s<>\"'`|\[\]()]+[^\s<>\"'`|\[\]().,;:!?]")
_URL_SLOT_RE = re.compile("\x00URL(\\d+)\x00")
# spans the citation pass must leave alone: code spans, markdown links/images, <autolinks>
_CITE_SKIP_RE = re.compile(r"(`+)(?:(?!\1).)+?\1|!?\[[^\]\n]*\]\([^)\n]*\)|<https?://[^>\s]+>", re.S)
_ARCHIVE_HOSTS = ("archive.org", "archive.today", "archive.ph", "archive.is", "archive.li", "archive.md",
                  "archive.vn", "ghostarchive.org", "webcitation.org")
_SCAN_HOSTS = ("urlscan.io",)


def _url_host(url: str) -> str:
    m = re.match(r"https?://(?:[^@/]*@)?([^/:?#]+)", url, re.I)
    host = (m.group(1) if m else "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _is_public_url(url: str) -> bool:
    host = _url_host(url)
    if not host or host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return "." in host


def url_class(url: str, estate=()) -> str:
    """The public source CLASS of a cited link (Rule 12 wording for the Source column)."""
    host = _url_host(url)
    if any(host == a or host.endswith("." + a) for a in _ARCHIVE_HOSTS):
        return "web archive capture"
    if any(host == s or host.endswith("." + s) for s in _SCAN_HOSTS):
        return "public web-scan capture"
    if any(host == d or host.endswith("." + d) for d in estate):
        return "live operator page"
    if url.lower().split("?", 1)[0].split("#", 1)[0].endswith(".pdf"):
        return "published document"
    return "published web page"


def url_label(url: str, estate=()) -> str:
    """A reader-facing label for a citation: source class, publisher host, capture date when known."""
    cls = url_class(url, estate)
    if cls == "web archive capture":
        m = re.search(r"/web/(\d{4})(\d{2})(\d{2})\d*", url)
        archived = re.sub(r"^https?://web\.archive\.org/web/\d+[a-z_]*/", "", url)
        orig = _url_host(archived) if archived != url else ""
        return cls + (f" of {orig}" if orig else "") + (f", {m.group(1)}-{m.group(2)}-{m.group(3)}" if m else "")
    return f"{cls}, {_url_host(url)}"


def _md_link_target(url: str) -> str:
    return url.replace("(", "%28").replace(")", "%29").replace(" ", "%20")


def cite_urls(md: str, refs: dict) -> str:
    """Every bare public URL outside code spans / existing links -> a hyperlinked `[n]`, registered
    in `refs` (url -> n, first-seen order). A non-public URL is internal working: dropped."""
    def one(m):
        url = m.group(0)
        if not _is_public_url(url):
            return "the case record"
        n = refs.setdefault(url, len(refs) + 1)
        return f"[\\[{n}\\]]({_md_link_target(url)})"

    out, pos = [], 0
    for m in _CITE_SKIP_RE.finditer(md):
        out.append(_URL_RE.sub(one, md[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_URL_RE.sub(one, md[pos:]))
    return "".join(out)


def references_md(refs: dict, label) -> str:
    """The References section body; `label(url)` returns the row's (already escaped) label."""
    lines = ["Each bracketed number in the text links to the public location below; open it to "
             "re-check the claim it supports. Archive captures are frozen copies and stay valid "
             "after the live page changes.", ""]
    for url, n in sorted(refs.items(), key=lambda kv: kv[1]):
        lines.append(f"- \\[{n}\\] {label(url)}: <{_md_link_target(url)}>")
    return "\n".join(lines)


# --------------------------------------------------------------------------- credentials in URLs
def strip_secret_params(url: str) -> str:
    """`url` without user-info and without any query/fragment parameter named in
    `secret_query_keys` (case-insensitive). Other parameters keep their original encoding."""
    m = re.match(r"(https?://)([^/?#]*@)?(.*)$", url, re.I | re.S)
    if not m:
        return url
    rest = m.group(3)
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    query = None
    if "?" in rest:
        rest, query = rest.split("?", 1)

    def keep(part: str) -> str:
        pairs = [p for p in re.split(r"[&;]", part) if p]
        kept = [p for p in pairs if unquote(p.split("=", 1)[0]).strip().lower() not in SECRET_QUERY_KEYS]
        return "&".join(kept)

    out = m.group(1) + rest
    if query is not None:
        q = keep(query)
        if q:
            out += "?" + q
    if frag:
        f = keep(frag) if "=" in frag else frag
        if f:
            out += "#" + f
    return out


def strip_secrets(text: str) -> str:
    """Every URL in `text` with its credentials removed (strip_secret_params). Never raises."""
    try:
        return _URL_RE.sub(lambda m: strip_secret_params(m.group(0)), text or "")
    except Exception:  # noqa: BLE001
        return text


# --------------------------------------------------------------------------- per-claim sources
# a host named in a claim; not an e-mail domain, not a file name, not part of a longer label
_HOST_RE = re.compile(r"(?<![\w@.\-/])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9])"
                      r"(?![\w@-]|\.[a-z0-9])", re.I)
_NOT_TLD = {"js", "json", "css", "html", "htm", "php", "png", "jpg", "jpeg", "gif", "svg", "ico",
            "txt", "xml", "md", "py", "exe", "apk", "aab", "zip", "pdf", "csv", "msi", "dmg", "jar",
            "sh", "inc", "llc", "ltd"}
_SOURCE_HOSTS = {"crt.sh", "rdap.org", "urlscan.io", "web.archive.org", "archive.org", "virustotal.com",
                 "otx.alienvault.com", "alienvault.com", "play.google.com", "realtimebidding.google.com",
                 "whoisxmlapi.com", "intelx.io", "sellers.json", "ads.txt"}
_CRTSH_RE = re.compile(r"crt\.sh[\s:#]*(?:id[\s:=#]*)?((?:\d{6,}(?:\s*(?:/|,|&|and)\s*)?)+)", re.I)
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_PACKAGE_RE = re.compile(r"(?<![\w.])((?:com|net|org|io|vn|app|co|me|in)\.[a-z0-9_]+(?:\.[a-z0-9_]+)*)(?![\w.])")
_PER_RULE = 2      # selectors cited per rule (a claim naming two hosts cites both)


def _hosts_in(claim: str, estate) -> tuple[list, list]:
    """(estate hosts the claim names, every host it names — estate first), in claim order."""
    found = []
    for m in _HOST_RE.finditer(claim):
        h = m.group(1).lower().rstrip(".")
        h = h[4:] if h.startswith("www.") else h
        if h.rsplit(".", 1)[-1] in _NOT_TLD or h in _SOURCE_HOSTS or h in found:
            continue
        if h not in estate and not has_known_tld(h):
            continue                       # `pgadmin.staging` (a split host) — not a resolvable name
        if _PACKAGE_RE.fullmatch(h) and h not in estate:
            continue                       # com.example.app — an app id, not a host
        found.append(h)
    est = [h for h in found if h in estate]
    return est, est + [h for h in found if h not in est]


def _selectors(claim: str, estate) -> dict:
    est, hosts = _hosts_in(claim, estate)
    ids = []
    for m in _CRTSH_RE.finditer(claim):
        ids += [i for i in re.findall(r"\d{6,}", m.group(1)) if i not in ids]
    return {"domain": hosts, "estate_domain": est, "crtsh_id": ids,
            "urlscan_uuid": list(dict.fromkeys(u.lower() for u in _UUID_RE.findall(claim))),
            "package": list(dict.fromkeys(_PACKAGE_RE.findall(claim)))}


def _links(claim: str, estate=()) -> tuple[list, list]:
    """([(url, class)], [match regex of every rule that produced a link])."""
    estate = {str(h).lower() for h in estate or ()}
    sel = _selectors(claim, estate)
    out: dict = {}
    used: list = []
    for rule in SOURCE_LINKS.values():
        try:
            if not re.search(rule["match"], claim, re.I):
                continue
            need = rule.get("needs") or ""
            values = sel.get(need, [])[:_PER_RULE] if need else [""]
            for v in values:
                url = rule["url"].format(**{need or "_": v, "apex": _registrable_apex(v) if v else ""})
                if _is_public_url(url):
                    out.setdefault(url, str(rule.get("class") or url_class(url, estate)))
                    if rule["match"] not in used:
                        used.append(rule["match"])
        except (KeyError, IndexError, ValueError, re.error):
            continue                       # a malformed analyst rule skips, never breaks a render
    return list(out.items()), used


def source_links(claim: str, estate=()) -> list:
    """[(url, class)] — the public pages that re-check `claim`, rebuilt from the selectors it names
    by the `source_links` rules. Only public URLs; deduplicated in rule order."""
    return _links(claim, estate)[0]


def vendor_classes(claim: str, covered=()) -> list:
    """Public source classes of the vendors/tools a claim names (Rule 12 wording), in table order.
    A vendor mention that one of the `covered` regexes also matches is already cited by a public
    link (crt.sh -> the crt.sh page) and is skipped."""
    out = []
    for pat, cls in PUBLIC_CLASS:
        if cls == "the case record" or cls in out:
            continue
        spans = [m.group(0) for m in re.finditer(pat, claim, re.I)]
        if any(not any(re.search(c, s, re.I) for c in covered) for s in spans):
            out.append(cls)
    return out


def cite_claim(claim: str, estate=(), labels: dict | None = None, require: bool = True) -> str:
    """`claim. Source: <class> URL; …` with every URL secret-stripped. A claim that already
    carries a public URL keeps it (the citation pass links it in place). Otherwise the public
    pages rebuilt by source_links() are appended; a source with no public page is named by its
    class with "(no public link)". With `require` a claim with no identifiable source at all is
    marked "case record (no public link)". `labels` collects url -> class for References. Never raises."""
    try:
        text = strip_secrets(str(claim if claim is not None else ""))
        if any(_is_public_url(u) for u in _URL_RE.findall(text)):
            return text
        links, used = _links(text, estate)
        named = vendor_classes(text, used)
        if not links and not named and not require:
            return text
        parts = [f"{cls} {url}" for url, cls in links]
        if named or not links:
            parts.append(f"{'; '.join(named) or 'case record'} (no public link)")
        if labels is not None:
            for url, cls in links:
                labels.setdefault(url, cls)
        body = text.rstrip()
        if body and body[-1] not in ".!?":
            body += "."
        return f"{body} Source: {'; '.join(parts)}."
    except Exception:  # noqa: BLE001
        return claim


def _min_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def finalize(md: str, estate=(), labels: dict | None = None, transform=None) -> str:
    """One snapshot document through the Rule 12 / Rule 21 pass: credentials stripped from every
    URL; vendor names scrubbed (and `transform`, e.g. third-party masking, applied) with URLs
    shielded so neither can mangle a link; every public URL -> hyperlinked `[n]`; non-public URLs
    dropped; a `# References` section appended. Never raises — on error returns the secret-stripped
    input (or the input itself)."""
    safe = strip_secrets(md)
    try:
        estate = {str(h).lower() for h in estate or ()}
        labels = labels or {}
        urls: list = []

        def _slot(m):
            urls.append(m.group(0))
            return f"\x00URL{len(urls) - 1}\x00"

        text = _URL_RE.sub(_slot, safe)
        text = "\n".join(scrub_vendors(line) for line in text.splitlines())
        if transform is not None:
            try:
                text = transform(text)
            except Exception as exc:  # noqa: BLE001 — degrade loudly, never ship unmasked silently
                sys.stderr.write(f"report_citations: transform failed ({exc!r}); text NOT transformed "
                                 f"(e.g. not masked) — review before sharing.\n")
        text = _URL_SLOT_RE.sub(lambda m: urls[int(m.group(1))], text)
        refs: dict = {}
        text = cite_urls(text, refs)
        if refs:
            def label(u):
                cls = labels.get(u)
                return _min_escape(f"{cls}, {_url_host(u)}" if cls else url_label(u, estate))
            text = text.rstrip() + "\n\n# References\n\n" + references_md(refs, label) + "\n"
        return text
    except Exception:  # noqa: BLE001
        return safe


def case_estate(case_dir: str = "", hosts=()) -> set:
    """The case's own hosts: `hosts` plus every host collected into `case_dir`/raw/. These are the
    hosts whose own page a claim may cite as "live operator page". Never raises."""
    out = {str(h).strip().lower() for h in hosts or () if str(h or "").strip()}
    try:
        raw = os.path.join(case_dir, "raw") if case_dir else ""
        if raw and os.path.isdir(raw):
            out |= {f[:-5].lower() for f in os.listdir(raw) if f.endswith(".json")}
    except OSError:
        pass
    return {h[4:] if h.startswith("www.") else h for h in out}
