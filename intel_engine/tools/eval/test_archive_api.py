#!/usr/bin/env python3
"""Regression test for archive_api.py: collecting archived JSON API endpoints and ingesting
them into the case KB as engine-collected facts with wayback provenance."""
from __future__ import annotations

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOLS)
for p in (TOOLS, os.path.join(ROOT, "tools", "kb"), os.path.join(ROOT, "WebPivot", "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import archive_api
from knowledge_base import KB


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    with tempfile.TemporaryDirectory() as tmp:
        case = "CASE-TEST-API"
        domain = "app-example.com"
        api_dir = os.path.join(tmp, "api")
        kb_dir = os.path.join(tmp, "kb")
        os.makedirs(kb_dir, exist_ok=True)

        # 1. Synthetic API files
        mock_manifest = [
            {
                "timestamp": "20260101120000",
                "slug": "policies_payment",
                "file": os.path.join(api_dir, "20260101120000_policies_payment.json"),
                "data": {
                    "title_en": "Payment Policy",
                    "content_zh": "平台支持Zalopay, momo等方式。用户需充值开通，佣金可提现，不予退款。",
                },
            },
            {
                "timestamp": "20260101120000",
                "slug": "settings_company",
                "file": os.path.join(api_dir, "20260101120000_settings_company.json"),
                "data": {
                    "name": "Tatao Tech Co.",
                    "icp": "京ICP备99999999号",
                },
            },
            {
                "timestamp": "20260101120000",
                "slug": "settings_footer",
                "file": os.path.join(api_dir, "20260101120000_settings_footer.json"),
                "data": {
                    "social": {
                        "facebook": "https://www.facebook.com/example",
                        "zalo": "https://zalo.me/12345678",
                    },
                    "company": {
                        "mapLocation": "21.0177,105.7811",
                    },
                },
            },
            {
                "timestamp": "20260101120000",
                "slug": "downloads",
                "file": os.path.join(api_dir, "20260101120000_downloads.json"),
                "data": {
                    "android": [
                        {
                            "app_name": "Test Live",
                            "version": "1.0.0",
                            "download_url": "https://cdn.sideload.example/app.apk",
                        }
                    ],
                    "ios": [
                        {
                            "app_name": "Test Live iOS",
                            "version": "1.0.0",
                            "download_url": "https://cdn.sideload.example/app.ipa",
                        }
                    ],
                },
            },
        ]

        # 2. Ingest
        n = archive_api.ingest_api_data(domain, case, mock_manifest, kb_dir=kb_dir)
        ok(n >= 9, f"ingest_api_data ingested all expected facts (got {n})")

        # 3. Verify in KB
        kb = KB(kb_dir)
        entity = kb.entity("domain", domain)
        facts = {f["attribute"]: f["value"] for f in entity.get("facts", [])}

        ok("payment_rails_observed" in facts and "Zalopay" in facts["payment_rails_observed"],
           "payment rails parsed and ingested as fact")
        ok("monetization_model_observed" in facts and "top-up" in facts["monetization_model_observed"],
           "monetization rules parsed and ingested as fact")
        ok(facts.get("operator_company_name") == "Tatao Tech Co.",
           "operator company name ingested")
        ok(facts.get("icp_licence_claim") == "京ICP备99999999号",
           "ICP licence claim ingested")
        ok("facebook" in facts.get("social_profile_facebook", ""),
           "social profile link ingested")
        ok(facts.get("geo_coordinates") == "21.0177,105.7811",
           "geo coordinates ingested")
        ok(facts.get("android_app_name") == "Test Live v1.0.0",
           "Android app name and version ingested")
        ok(facts.get("sideload_host") == "cdn.sideload.example",
           "sideload host identified and ingested as medium confidence fact")

        # Check provenance
        sample_fact = entity["facts"][0]
        ok(sample_fact.get("source") == "wayback" and sample_fact.get("collector") == "wayback/archive_api",
           "proper engine provenance attributed on facts (source=wayback, collector=wayback/archive_api)")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"[{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
