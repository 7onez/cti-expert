#!/usr/bin/env python3
"""
wp_suppliers.py — derive a subject organisation's SUPPLIER MAP from a case's collected raws.

    python3 wp_suppliers.py CASE-0001 --subject example.com[,example.net] [--out PATH] [--kb DIR] [--print]

Reads `cases/<id>/raw/*.json` (pivot_extract output — no network, no credits) and writes
`cases/<id>/suppliers.json` (contract C3):

    {"subjects": [...], "suppliers": [{"name", "category", "evidence": [{"kind", "value", "host"}],
     "confidence": "high|medium|low"}], "generated_utc", "compiled_to", "relation", "caveats", "inputs"}

Evidence kinds and where they are read from in each raw:
  txt_verification  artifacts.mail.txt_verifications[].record, artifacts.mail.txt_records[]
  spf_include       artifacts.mail.spf.includes[], pivots[kind=spf_include]
  mx                artifacts.mail.mx_hosts[]  (named by mail_providers.json via wp_recon._classify_mx)
  ns                artifacts.whois.name_servers[]
  cert_issuer       artifacts.tls_cert.issuer
  cname             artifacts.cnames[] = [{host, chain}]  (wp_recon.detect_cnames; first matching hop)
  document          artifacts.docmeta.files[].meta (producer/creator_tool/software/title), pivots[kind=doc_software]

The pattern -> supplier table is DATA in references/suppliers.json. Only hosts at or under a
subject apex count; a token, include or host matching no row is ignored. Confidence comes from
the table's `confidence` group (exact TXT/SPF/MX/NS on the subject's own apex = high, a document
mention = low); a supplier takes the highest confidence across its evidence.

ATTRIBUTION RAIL: a supplier is a relationship OF the subject, shared with every other customer of
that vendor. This module never writes an edge or an operator link; with --kb it records one
`supplier` FACT per (subject apex, supplier) and nothing else.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_refs import ref_path, load_ref  # noqa: E402
from wp_recon import _classify_mx  # noqa: E402 — mail_providers.json is the one MX table

ENGINE = os.path.dirname(os.path.dirname(HERE))
COLLECTOR = "wp_suppliers"

# Minimal fallback: one row per group, so a broken data file still yields a (thinner) map and
# never an attribution-shaped output.
_FALLBACK = {
    "txt_tokens": {"ms=": {"supplier": "Microsoft 365", "category": "email & productivity"}},
    "spf_includes": {"sendgrid.net": {"supplier": "SendGrid (Twilio)", "category": "email delivery"}},
    "cname_targets": {".okta.com": {"supplier": "Okta", "category": "identity provider"}},
    "ns_hosts": {".ns.cloudflare.com": {"supplier": "Cloudflare", "category": "DNS hosting"}},
    "cert_issuers": {"digicert": {"supplier": "DigiCert", "category": "certificate authority"}},
    "document_keywords": {"docusign": {"supplier": "DocuSign", "category": "e-signature"}},
    "confidence": {"txt_verification": {"apex": "high", "subdomain": "medium"},
                   "spf_include": {"apex": "high", "subdomain": "medium"},
                   "mx": {"apex": "high", "subdomain": "medium"},
                   "ns": {"apex": "high", "subdomain": "medium"},
                   "cname": {"apex": "medium", "subdomain": "medium"},
                   "cert_issuer": {"apex": "medium", "subdomain": "medium"},
                   "document": {"apex": "low", "subdomain": "low"}},
    "caveats": ["A supplier is a third-party relationship of the subject, never an operator link."],
}
_REF = load_ref(ref_path(__file__, "suppliers.json"), _FALLBACK)


def _rows(group):
    return {str(k).lower(): v for k, v in (_REF.get(group) or {}).items() if isinstance(v, dict)}


TXT_TOKENS = _rows("txt_tokens")
SPF_INCLUDES = _rows("spf_includes")
CNAME_TARGETS = _rows("cname_targets")
NS_HOSTS = _rows("ns_hosts")
CERT_ISSUERS = _rows("cert_issuers")
DOC_KEYWORDS = _rows("document_keywords")
CONFIDENCE = _REF.get("confidence") or _FALLBACK["confidence"]
CAVEATS = list(_REF.get("caveats") or _FALLBACK["caveats"])
_RANK = {"high": 3, "medium": 2, "low": 1}
_DOC_FIELDS = ("producer", "creator_tool", "software", "title")
RELATION = ("supplier of the subject — a third-party relationship shared with every other "
            "customer of the vendor; never an operator link")


def _host_match(host: str, table: dict):
    """First row whose signature matches `host`: '.x' suffix, '~x' substring, else exact/parent."""
    h = (host or "").lower().rstrip(".")
    if not h:
        return None
    for sig in sorted(table, key=lambda s: (-len(s), s)):  # most specific first, deterministic
        if sig.startswith("~"):
            hit = sig[1:] in h
        elif sig.startswith("."):
            hit = h.endswith(sig)
        else:
            hit = h == sig or h.endswith("." + sig)
        if hit:
            return table[sig]
    return None


def _txt_match(record: str):
    low = (record or "").strip().strip('"').lower()
    for prefix in sorted(TXT_TOKENS, key=lambda s: (-len(s), s)):
        if low.startswith(prefix):
            return TXT_TOKENS[prefix]
    return None


def _mail_row(name: str) -> dict:
    """A mail provider named by mail_providers.json, categorised from any supplier row of the same
    name (Proofpoint -> email security), else plain email hosting."""
    for table in (SPF_INCLUDES, TXT_TOKENS):
        for row in table.values():
            if row.get("supplier") == name and row.get("category"):
                return {"supplier": name, "category": row["category"]}
    return {"supplier": name, "category": "email hosting"}


def _scope(host: str, subjects) -> str | None:
    """'apex' / 'subdomain' when `host` sits at or under a subject apex, else None."""
    h = (host or "").lower().rstrip(".")
    h = h[4:] if h.startswith("www.") else h
    for s in subjects:
        if h == s:
            return "apex"
        if h.endswith("." + s):
            return "subdomain"
    return None


def _confidence(kind: str, where: str) -> str:
    row = CONFIDENCE.get(kind) or {}
    return str(row.get(where) or "low")


def _url_host(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", str(url or ""), re.I)
    return m.group(1).lower() if m else ""


def _evidence_from_raw(raw: dict, subjects):
    """Yield (kind, value, host, supplier_row, where) for every matched item in one raw."""
    meta = raw.get("meta") or {}
    art = raw.get("artifacts") or {}
    host = str(meta.get("host") or "").lower()
    where = _scope(host, subjects)
    pivots = [p for p in (raw.get("pivots") or []) if isinstance(p, dict)]
    if where:
        mail = art.get("mail") or {}
        txts = [tv.get("record") for tv in (mail.get("txt_verifications") or []) if isinstance(tv, dict)]
        txts += list(mail.get("txt_records") or [])
        for rec in txts:
            row = _txt_match(str(rec or ""))
            if row:
                yield "txt_verification", str(rec).strip().strip('"')[:200], host, row, where
        spf = mail.get("spf") or {}
        incs = list(spf.get("includes") or []) + [p.get("value") for p in pivots
                                                   if p.get("kind") == "spf_include"]
        for inc in incs:
            inc = str(inc or "").lower().rstrip(".")
            row = _host_match(inc, SPF_INCLUDES)
            if not row and inc:
                name = _classify_mx(inc)
                row = _mail_row(name) if name else None
            if row:
                yield "spf_include", inc, host, row, where
        for mx in mail.get("mx_hosts") or []:
            name = _classify_mx(str(mx or ""))
            if name:
                yield "mx", str(mx).lower().rstrip("."), host, _mail_row(name), where
        for ns in (art.get("whois") or {}).get("name_servers") or []:
            row = _host_match(str(ns or ""), NS_HOSTS)
            if row:
                yield "ns", str(ns).lower().rstrip("."), host, row, where
        cert = art.get("tls_cert") or {}
        issuer = str(cert.get("issuer") or "")
        cert_host = str(cert.get("host") or host).lower()
        cert_where = _scope(cert_host, subjects)
        if issuer and cert_where:
            low = issuer.lower()
            for key in sorted(CERT_ISSUERS, key=lambda s: (-len(s), s)):
                if key in low:
                    yield "cert_issuer", issuer[:120], cert_host, CERT_ISSUERS[key], cert_where
                    break
        for ent in art.get("cnames") or []:
            if not isinstance(ent, dict):
                continue
            alias = str(ent.get("host") or "").lower().rstrip(".")
            alias_where = _scope(alias, subjects)
            for hop in ent.get("chain") or []:
                row = _host_match(str(hop or ""), CNAME_TARGETS)
                if row and alias_where:
                    yield "cname", str(hop).lower().rstrip("."), alias, row, alias_where
                    break
    # documents: the FILE's own host must sit under a subject (a same-site document)
    docs = []
    for f in ((art.get("docmeta") or {}).get("files") or []):
        if isinstance(f, dict):
            m = f.get("meta") or {}
            text = " ".join(str(m.get(k) or "") for k in _DOC_FIELDS)
            docs.append((_url_host(f.get("url")) or host, text))
    if where:
        docs += [(host, str(p.get("value") or "")) for p in pivots if p.get("kind") == "doc_software"]
    for dhost, text in docs:
        dwhere = _scope(dhost, subjects)
        low = text.lower()
        if not dwhere or not low.strip():
            continue
        for kw in sorted(DOC_KEYWORDS):
            if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", low):
                yield "document", f"metadata mentions '{kw}'", dhost, DOC_KEYWORDS[kw], dwhere


def build(raws, subjects, generated_utc: str | None = None) -> dict:
    """Pure builder: `raws` = iterable of parsed raw dicts. Deterministic for the same input and
    `generated_utc`; never emits an edge, a link or an operator field."""
    subjects = sorted({str(s).lower().strip().rstrip(".") for s in subjects if str(s).strip()})
    subjects = [s[4:] if s.startswith("www.") else s for s in subjects]
    by_name: dict = {}
    n_read = n_scope = 0
    compiled = []
    for raw in raws:
        if not isinstance(raw, dict):
            continue
        n_read += 1
        meta = raw.get("meta") or {}
        hit = False
        for kind, value, host, row, where in _evidence_from_raw(raw, subjects):
            name = str(row.get("supplier") or "").strip()
            if not name:
                continue
            hit = True
            conf = _confidence(kind, where)
            ent = by_name.setdefault(name, {})
            key = (kind, value, host)
            prev = ent.get(key)
            if not prev or _RANK[conf] > _RANK[prev[0]]:
                ent[key] = (conf, str(row.get("category") or "other"))
        if hit:
            n_scope += 1
            if meta.get("collected_at"):
                compiled.append(str(meta["collected_at"]))
    suppliers = []
    for name, ent in by_name.items():
        ranked = sorted(ent.items(), key=lambda kv: (-_RANK[kv[1][0]], kv[0]))
        suppliers.append({
            "name": name,
            "category": ranked[0][1][1],
            "evidence": [{"kind": k, "value": v, "host": h, "confidence": c}
                         for (k, v, h), (c, _cat) in sorted(ent.items())],
            "confidence": ranked[0][1][0],
        })
    suppliers.sort(key=lambda s: (-_RANK[s["confidence"]], s["name"].lower()))
    return {
        "subjects": subjects,
        "relation": RELATION,
        "suppliers": suppliers,
        "generated_utc": generated_utc,
        "compiled_to": max(compiled)[:10] if compiled else None,
        "inputs": {"raws_read": n_read, "raws_with_evidence": n_scope},
        "caveats": CAVEATS,
    }


def case_dir(case: str) -> str:
    """cases/<id> under $INTEL_HOME. The id must match the shared case-ID rule
    (wp_appliance._CASE_RE); a path, a slash or a leading dot raises ValueError."""
    from wp_appliance import _CASE_RE  # the one case-ID rule
    if not _CASE_RE.fullmatch(str(case)):
        raise ValueError(f"invalid case id {case!r} — a bare id, not a path")
    return os.path.join(os.environ.get("INTEL_HOME") or ENGINE, "cases", case)


def load_raws(cdir: str):
    out = []
    for p in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(p, encoding="utf-8") as fh:
                out.append(json.load(fh))
        except (OSError, ValueError):
            continue
    return out


def write_kb_facts(doc: dict, kb_root: str, case: str, evidence_ref: str) -> int:
    """One `supplier` FACT per (subject apex, supplier) — never an edge (attribution rail)."""
    kb_dir = os.path.join(ENGINE, "tools", "kb")
    if kb_dir not in sys.path:
        sys.path.insert(0, kb_dir)
    from knowledge_base import KB  # noqa: E402
    kb = KB(kb_root, case=case)
    observed = doc.get("generated_utc") or ""
    n = 0
    for s in doc["suppliers"]:
        apexes = sorted({next((x for x in doc["subjects"] if e["host"] == x or e["host"].endswith("." + x)), "")
                         for e in s["evidence"]} - {""})
        for apex in apexes:
            kb.add_fact("domain", apex, "supplier", f"{s['name']} ({s['category']})", "suppliers",
                        COLLECTOR, observed, s["confidence"], evidence_ref, case=case)
            n += 1
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Case raws -> cases/<id>/suppliers.json (C3 supplier map).")
    ap.add_argument("case", help="case id (cases/<id>/raw/*.json is read)")
    ap.add_argument("--subject", required=True,
                    help="subject apex domain(s), comma-separated; only hosts at/under them count")
    ap.add_argument("--out", help="output path (default cases/<id>/suppliers.json)")
    ap.add_argument("--kb", help="also record one `supplier` fact per subject/supplier in this KB dir")
    ap.add_argument("--print", action="store_true", help="print the JSON to stdout")
    a = ap.parse_args(argv)
    try:
        cdir = case_dir(a.case)
    except ValueError as exc:
        print(f"[suppliers] {exc}", file=sys.stderr)
        return 2
    if not os.path.isdir(os.path.join(cdir, "raw")):
        print(f"[suppliers] no raw/ directory under {cdir}", file=sys.stderr)
        return 2
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = build(load_raws(cdir), a.subject.split(","), generated_utc=now)
    out = a.out or os.path.join(cdir, "suppliers.json")
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, out)
    if a.kb:
        n = write_kb_facts(doc, a.kb, a.case, os.path.relpath(out, os.path.dirname(cdir)))
        print(f"[suppliers] {n} supplier fact(s) recorded (facts only, no edges)", file=sys.stderr)
    print(f"[suppliers] {len(doc['suppliers'])} supplier(s) -> {out}", file=sys.stderr)
    if a.print:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
