#!/usr/bin/env python3
"""Push WebPivot case findings into the Intel Working Base server.

Reads the per-host ``cases/<case>/raw/<host>.json`` files a WebPivot run
already produced and POSTs their WHOIS + FOFA findings to the working-base
ingest endpoint, which persists them natively (whois_lookup DomainRecord,
fofa FofaSearch/FofaSearchResult) and emits the cross-tool Sightings. This is
what stops working-base from re-querying WhoisXML/FOFA for infrastructure
WebPivot already looked up.

Transport only — no re-collection. WebPivot keeps running off-platform (laptop
/ research VPS) for egress hygiene; only this push touches the server.

Config (env, or --url/--token flags):
  WORKINGBASE_INGEST_URL   e.g. https://<host>.ohmybuddha.store/tools/webpivot/ingest/
  WORKINGBASE_TOKEN        shared secret matching the server's WEBPIVOT_INGEST_TOKEN

Usage:
  python3 tools/kb/push_workingbase.py cases/<case>/raw/*.json --case CASE-0001
  python3 tools/kb/push_workingbase.py cases/<case>            # a case dir (finds raw/*.json)
  python3 tools/kb/push_workingbase.py cases/<case> --dry-run  # print payload, don't send

Zero dependencies (stdlib urllib) to match the WebPivot skill's ethos.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _load(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except Exception as e:  # noqa: BLE001
        print(f'[!] skip {path}: {e}', file=sys.stderr)
        return None


def _collect_fofa(result):
    """Flatten every FOFA block across a result's pivots into one list.

    Each pivot's live_results may carry a favicon/body reverse ('fofa') and/or
    an IP reverse ('fofa_ip_reverse'); each is a {query,total,results} block.
    """
    blocks = []
    seen_queries = set()
    for piv in (result.get('pivots') or []):
        lr = piv.get('live_results') or {}
        for key in ('fofa', 'fofa_ip_reverse'):
            fb = lr.get(key)
            if not isinstance(fb, dict) or fb.get('error') or not fb.get('results'):
                continue
            q = fb.get('query') or ''
            if q in seen_queries:      # same query can appear on multiple pivots
                continue
            seen_queries.add(q)
            blocks.append({'query': q, 'total': fb.get('total'), 'results': fb['results']})
    return blocks


def build_payload(files, case_code=None):
    hosts = []
    for f in files:
        result = _load(f)
        if not result:
            continue
        host = (result.get('meta') or {}).get('host') or Path(f).stem
        whois = (result.get('artifacts') or {}).get('whois')
        fofa = _collect_fofa(result)
        if not whois and not fofa:
            continue          # nothing persistable in this file
        entry = {'host': host}
        if whois:
            entry['whois'] = whois
        if fofa:
            entry['fofa'] = fofa
        hosts.append(entry)
    payload = {'hosts': hosts}
    if case_code:
        payload['case'] = case_code
    return payload


def expand_inputs(inputs):
    """Accept files, globs, and case directories → a flat list of raw/*.json paths."""
    files = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            raw = p / 'raw'
            base = raw if raw.is_dir() else p
            files.extend(sorted(str(x) for x in base.glob('*.json')))
        elif any(c in item for c in '*?['):
            files.extend(sorted(glob.glob(item)))
        elif p.is_file():
            files.append(str(p))
        else:
            print(f'[!] not found: {item}', file=sys.stderr)
    return files


def post(url, token, payload, timeout=60):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {'error': e.reason}
    except Exception as e:  # noqa: BLE001
        return None, {'error': str(e)}


def main():
    ap = argparse.ArgumentParser(description='Push WebPivot case findings to Intel Working Base.')
    ap.add_argument('inputs', nargs='+', help='raw/*.json files, a glob, or a case dir')
    ap.add_argument('--case', help='working-base Case code to scope the writes to')
    ap.add_argument('--url', default=os.environ.get('WORKINGBASE_INGEST_URL', ''),
                    help='ingest endpoint URL (or env WORKINGBASE_INGEST_URL)')
    ap.add_argument('--token', default=os.environ.get('WORKINGBASE_TOKEN', ''),
                    help='ingest token (or env WORKINGBASE_TOKEN)')
    ap.add_argument('--dry-run', action='store_true', help='print the payload, do not send')
    args = ap.parse_args()

    files = expand_inputs(args.inputs)
    if not files:
        ap.error('no input JSON files found')

    payload = build_payload(files, args.case)
    n_hosts = len(payload['hosts'])
    n_whois = sum(1 for h in payload['hosts'] if h.get('whois'))
    n_fofa = sum(len(h.get('fofa') or []) for h in payload['hosts'])
    print(f'[*] {len(files)} file(s) → {n_hosts} host(s) with data '
          f'({n_whois} whois, {n_fofa} fofa search block(s))', file=sys.stderr)

    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    if not n_hosts:
        print('[!] nothing to push', file=sys.stderr)
        return
    if not args.url or not args.token:
        ap.error('set --url/--token or WORKINGBASE_INGEST_URL/WORKINGBASE_TOKEN')

    status, resp = post(args.url, args.token, payload)
    print(json.dumps(resp, indent=2, ensure_ascii=False))
    if status != 200:
        print(f'[!] server returned HTTP {status}', file=sys.stderr)
        sys.exit(1)
    print(f'[✓] pushed: {resp.get("whois")} whois, {resp.get("fofa")} fofa', file=sys.stderr)


if __name__ == '__main__':
    main()
