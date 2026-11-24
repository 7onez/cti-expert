#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml"]
# ///
"""kit_rules_import.py — seed the named kit-signature library from the public phish.report IOK
rule set (https://github.com/phish-report/IOK, ODbL-1.0) into the GIT-IGNORED cache.

The rules are never copied into this repository. `update` downloads the IOK repository tarball
ONCE through the shared transport (wp_http), reads `indicators/*.yml` in memory (nothing is
extracted to disk; a member outside `indicators/` is ignored), converts what the matcher can
express (wp_iok.convert_rule — anything else is skipped with its reason) and writes the cache
atomically. wp_kitsig.match reads it after the tracked rules: an imported match is a kit_link-rung
FACT (source `iok`), never an edge, a cluster member or an operator lead; a `commodity` one is
noise context and never a pivot.

  uv run scripts/kit_rules_import.py update [--out PATH] [--source URL]
  uv run scripts/kit_rules_import.py status [--out PATH]

Default PATH: $CTI_KIT_RULES_CACHE, else $INTEL_HOME/cache/kit_rules/iok.json (default
intel_engine/cache/kit_rules/iok.json). A failed download, or a tarball with zero convertible
rules, leaves an existing cache untouched and exits non-zero.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import sys
import tempfile

_WP = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                                    "intel_engine", "WebPivot", "tools"))
if _WP not in sys.path:
    sys.path.append(_WP)
import wp_http  # noqa: E402 — the one transport
import wp_iok  # noqa: E402 — the pure converter + its reference settings
import wp_kitsig  # noqa: E402 — the cache path the matcher reads
import api_usage  # noqa: E402 — a free download is still ledgered (credits=0)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def download(url):
    """(bytes, None) or (None, reason). Never raises."""
    r = wp_http.request(url, timeout=wp_iok.TIMEOUT, retries=1, decode=False,
                        max_body=wp_iok.MAX_TARBALL_BYTES + 1)
    if r.status is None:
        reason = r.error or "no response"
    elif not r.ok:
        reason = r.http_error
    elif not r.body:
        reason = "empty body"
    elif len(r.body) > wp_iok.MAX_TARBALL_BYTES:
        reason = f"tarball larger than max_tarball_bytes ({wp_iok.MAX_TARBALL_BYTES})"
    else:
        api_usage.record("phish_report_iok", "iok_tarball_download", credits=0, query=url,
                         results=len(r.body))
        return r.body, None
    api_usage.record("phish_report_iok", "iok_tarball_download", credits=0, query=url, ok=False)
    return None, reason


def write_atomic(path, doc):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iok-", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)              # mkstemp's 0600 would hide the cache from other readers
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _reasons(skipped):
    return collections.Counter(s["reason"] for s in skipped if s.get("file") != "*")


def cmd_update(out, source, load_yaml=None) -> int:
    if load_yaml is None:
        import yaml  # noqa: WPS433 — PEP 723 dependency; `status` needs no YAML
        load_yaml = yaml.safe_load
    data, err = download(source)
    if err:
        print(f"[iok] download failed ({err}); cache left untouched: {out}", file=sys.stderr)
        return 2
    try:
        res = wp_iok.convert_tarball(data, load_yaml)
    except Exception as exc:  # noqa: BLE001 — a corrupt tarball is a failed update, not a crash
        print(f"[iok] tarball unreadable ({exc}); cache left untouched: {out}", file=sys.stderr)
        return 3
    if not res["rules"]:
        print(f"[iok] zero convertible rules in {res['counts']['files']} file(s); cache left "
              f"untouched: {out}", file=sys.stderr)
        for reason, n in _reasons(res["skipped"]).most_common():
            print(f"    {n:4d}  {reason}", file=sys.stderr)
        return 3
    doc = {"source": source, "licence": wp_iok.LICENCE, "attribution": wp_iok.ATTRIBUTION,
           "fetched_at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
           "tarball_sha256": hashlib.sha256(data).hexdigest(), "commit": res["commit"],
           "counts": res["counts"], "skipped": res["skipped"], "rules": res["rules"]}
    write_atomic(out, doc)
    c = res["counts"]
    print(f"[iok] {c['imported']} imported, {c['skipped']} skipped of {c['files']} file(s) "
          f"(limited {c['prevalence']['limited']}, commodity {c['prevalence']['commodity']}) -> {out}")
    print(f"      tarball sha256 {doc['tarball_sha256']}" + (f", commit {res['commit']}"
                                                            if res["commit"] else ""))
    for reason, n in _reasons(res["skipped"]).most_common():
        print(f"    {n:4d}  skipped: {reason}")
    if any(s.get("file") == "*" for s in res["skipped"]):
        print("      [!] max_members reached: the tarball was NOT read to the end")
    print(f"      licence {wp_iok.LICENCE}: {wp_iok.ATTRIBUTION}")
    return 0


def cmd_status(out) -> int:
    try:
        with open(out, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        print(f"[iok] no cache at {out} — run: uv run scripts/kit_rules_import.py update")
        return 1
    except (OSError, ValueError) as exc:
        print(f"[iok] cache at {out} unreadable ({exc})")
        return 1
    c = doc.get("counts") or {}
    age = ""
    try:
        when = datetime.datetime.strptime(doc.get("fetched_at", ""), "%Y-%m-%dT%H:%M:%SZ")
        days = (_now().replace(tzinfo=None) - when).total_seconds() / 86400
        age = f" ({days:.1f} day(s) old)"
    except ValueError:
        pass
    prev = c.get("prevalence") or {}
    print(f"[iok] {out}")
    print(f"      fetched_at {doc.get('fetched_at')}{age}; source {doc.get('source')}")
    print(f"      files {c.get('files')}, imported {c.get('imported')}, skipped {c.get('skipped')}"
          f" (limited {prev.get('limited')}, commodity {prev.get('commodity')}); "
          f"loadable now: {len(wp_kitsig.imported_rules(out))}")
    print(f"      tarball sha256 {doc.get('tarball_sha256')}; commit {doc.get('commit')}; "
          f"licence {doc.get('licence')}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="seed the kit-signature cache from phish.report IOK")
    sub = ap.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("update", help="download IOK, convert, write the cache atomically")
    up.add_argument("--out", default=None, help="cache file (default: the matcher's cache path)")
    up.add_argument("--source", default=wp_iok.SOURCE_URL, help="tarball URL")
    st = sub.add_parser("status", help="what the cache holds (no network)")
    st.add_argument("--out", default=None, help="cache file (default: the matcher's cache path)")
    a = ap.parse_args(argv)
    out = a.out or wp_kitsig.imported_cache_path()
    if a.cmd == "update":
        return cmd_update(out, a.source)
    return cmd_status(out)


if __name__ == "__main__":
    raise SystemExit(main())
