"""Wayback Archive API Collector & Ingester.

Fetches historical JSON API endpoints archived by the Internet Archive for a domain,
stores them under cases/<case>/api/<domain>/ with provenance, and ingests the operator's
own published configuration (payment policies, company aliases, app downloads, ICP claims,
and social handles) into the case knowledge base.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.parse
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP_TOOLS = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")

for p in (WP_TOOLS, KB_TOOLS, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import wp_net
except ImportError:
    wp_net = None

try:
    from knowledge_base import KB
except ImportError:
    KB = None


def cdx_api_urls(domain: str, timeout: int = 45) -> list[dict[str, str]]:
    """Query Wayback CDX for all /api/* endpoints under `domain`."""
    if not wp_net:
        return []
    clean_domain = domain.strip().lower()
    url = (f"https://web.archive.org/cdx/search/cdx?url={clean_domain}/api/*"
           f"&output=json&fl=timestamp,original,statuscode,mimetype,digest&collapse=digest&limit=200")
    try:
        _, status, _, body = wp_net.fetch(url, timeout=timeout)
        if status != 200 or not body:
            return []
        rows = json.loads(body)
        if len(rows) <= 1:
            return []
        headers, data = rows[0], rows[1:]
        out = []
        for r in data:
            row = dict(zip(headers, r))
            if row.get("statuscode") == "200":
                out.append(row)
        return out
    except Exception:  # noqa: BLE001
        return []


def collect_api_endpoints(domain: str, case: str, out_dir: str | None = None,
                          cdx_records: list[dict[str, str]] | None = None) -> list[dict[str, Any]]:
    """Download archived API endpoints and save to cases/<case>/api/<domain>/."""
    clean_domain = domain.strip().lower()
    target_dir = out_dir or os.path.join(ROOT, "cases", case, "api", clean_domain)
    os.makedirs(target_dir, exist_ok=True)

    records = cdx_records if cdx_records is not None else cdx_api_urls(clean_domain)
    manifest = []

    for r in records:
        ts = r.get("timestamp") or "0"
        orig = r.get("original") or ""
        if not orig:
            continue
        path_match = re.search(r"/api/([a-zA-Z0-9_\-\./]+)", orig)
        slug = path_match.group(1).replace("/", "_").replace(".", "_") if path_match else "endpoint"
        filename = f"{ts}_{slug}.json"
        filepath = os.path.join(target_dir, filename)

        wb_url = f"https://web.archive.org/web/{ts}id_/{orig}"
        data = None
        if os.path.exists(filepath):
            try:
                data = json.load(open(filepath, encoding="utf-8"))
            except Exception:
                pass

        if data is None and wp_net:
            try:
                _, st, _, body = wp_net.fetch(wb_url, timeout=40)
                if st == 200 and body:
                    try:
                        data = json.loads(body)
                        with open(filepath, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                    except Exception:
                        continue
            except Exception:
                continue

        if data is not None:
            sha = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()
            manifest.append({
                "timestamp": ts,
                "original_url": orig,
                "slug": slug,
                "file": filepath,
                "sha256": sha,
                "data": data,
            })

    # Save manifest
    with open(os.path.join(target_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump([
            {k: v for k, v in m.items() if k != "data"}
            for m in manifest
        ], f, indent=2)

    return manifest


def ingest_api_data(domain: str, case: str, manifest: list[dict[str, Any]],
                    kb_dir: str | None = None) -> int:
    """Ingest structured facts and edges from collected API files into the KB."""
    if not KB:
        return 0
    clean_domain = domain.strip().lower()
    kb_path = kb_dir or os.path.join(ROOT, "knowledge")
    kb = KB(kb_path)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    collector = "wayback/archive_api"
    count = 0

    for item in manifest:
        data = item.get("data")
        slug = item.get("slug", "")
        ev_ref = os.path.relpath(item["file"], ROOT) if os.path.exists(item["file"]) else item["file"]
        ts = item.get("timestamp") or now

        if "policies_payment" in slug and isinstance(data, dict):
            # Payment rails and monetization policy
            title = data.get("title_zh") or data.get("title_en") or "Payment"
            content = data.get("content_zh") or data.get("content_en") or ""
            kb.add_fact("domain", clean_domain, "payment_policy_title", title, "wayback", collector, ts, "high", ev_ref)
            count += 1
            if "Zalopay" in content or "momo" in content or "viettel" in content:
                kb.add_fact("domain", clean_domain, "payment_rails_observed",
                            "Zalopay, Momo, Shopeepay, VNPT Money, Viettel Money, VN bank transfer",
                            "wayback", collector, ts, "high", ev_ref)
                count += 1
            if "充值" in content or "提现" in content or "佣金" in content:
                kb.add_fact("domain", clean_domain, "monetization_model_observed",
                            "balance top-up required for features; distribution commission & rewards withdrawable; non-refundable",
                            "wayback", collector, ts, "high", ev_ref)
                count += 1

        elif ("settings_company" in slug or "company_i18n" in slug) and isinstance(data, dict):
            # Company names, descriptions, ICP licence claims
            name = data.get("name")
            if name:
                kb.add_fact("domain", clean_domain, "operator_company_name", str(name), "wayback", collector, ts, "high", ev_ref)
                count += 1
            icp = data.get("icp")
            if icp:
                kb.add_fact("domain", clean_domain, "icp_licence_claim", str(icp), "wayback", collector, ts, "high", ev_ref)
                count += 1
            # i18n variant check
            for lang in ("vi", "en", "zh", "ru"):
                sub = data.get(lang)
                if isinstance(sub, dict):
                    if sub.get("name"):
                        kb.add_fact("domain", clean_domain, f"company_alias_{lang}", str(sub["name"]), "wayback", collector, ts, "high", ev_ref)
                        count += 1
                    if sub.get("icp"):
                        kb.add_fact("domain", clean_domain, f"icp_licence_{lang}", str(sub["icp"]), "wayback", collector, ts, "high", ev_ref)
                        count += 1

        elif "settings_footer" in slug and isinstance(data, dict):
            # Social media profiles and footer links
            social = data.get("social") or {}
            for net, link in social.items():
                if link and str(link).startswith("http"):
                    kb.add_fact("domain", clean_domain, f"social_profile_{net}", str(link), "wayback", collector, ts, "high", ev_ref)
                    count += 1
            comp = data.get("company") or {}
            if comp.get("mapLocation"):
                kb.add_fact("domain", clean_domain, "geo_coordinates", str(comp["mapLocation"]), "wayback", collector, ts, "high", ev_ref)
                count += 1

        elif "downloads" in slug and isinstance(data, dict):
            # App bundles and download endpoints
            for platform in ("android", "ios"):
                apps = data.get(platform) or []
                for a in apps:
                    if isinstance(a, dict):
                        app_name = a.get("app_name")
                        dl_url = a.get("download_url")
                        version = a.get("version")
                        if app_name:
                            kb.add_fact("domain", clean_domain, f"{platform}_app_name", f"{app_name} v{version}", "wayback", collector, ts, "high", ev_ref)
                            count += 1
                        if dl_url:
                            kb.add_fact("domain", clean_domain, f"{platform}_download_url", str(dl_url), "wayback", collector, ts, "high", ev_ref)
                            count += 1
                            # Add sideload host reference
                            u = urllib.parse.urlparse(dl_url)
                            if u.hostname:
                                kb.add_fact("domain", clean_domain, "sideload_host", u.hostname, "wayback", collector, ts, "medium", ev_ref)
                                count += 1

    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Collect and ingest archived Wayback API endpoints into a case.")
    ap.add_argument("domain", help="Target domain (e.g. example.com)")
    ap.add_argument("--case", required=True, help="Case identifier (e.g. CASE-0001)")
    ap.add_argument("--kb", default=None, help="Knowledge base directory (default: knowledge)")
    args = ap.parse_args(argv)

    print(f"Collecting archived APIs for {args.domain} (case: {args.case})...")
    manifest = collect_api_endpoints(args.domain, args.case)
    print(f"Collected {len(manifest)} API endpoint payload(s).")
    n = ingest_api_data(args.domain, args.case, manifest, kb_dir=args.kb)
    print(f"Ingested {n} facts into the knowledge base.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
