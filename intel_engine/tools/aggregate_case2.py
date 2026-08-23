#!/usr/bin/env python3
"""Aggregate a case's per-host pivot_extract JSON into:
  1) enriched_pivots.csv  — one row per host, all pivotable fields
  2) shared_pivots.md     — strong artifacts shared by >=2 hosts (same-operator bridges)
  3) app_downloads.txt    — every app-download URL found (feed to BinaryPivot)
Privacy/registrar contact values are flagged as noise, not dropped.

Usage: python3 aggregate_case2.py <CASE-ID>   (reads and writes cases/<CASE-ID>/)"""
import json, os, csv, glob, re, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (tools/..)
CASE = sys.argv[1] if len(sys.argv) > 1 else "CASE-0001"
RAW = os.path.join(ROOT, "cases", CASE, "raw")          # resolve from repo root, not cwd
# Case deliverables live with the case, never in the cross-case KB — `knowledge/` holds
# entities/edges/cached payloads only.
OUTD = os.path.join(ROOT, "cases", CASE)
os.makedirs(OUTD, exist_ok=True)

# Cloudflare edge ranges. 104.16.0.0/12 spans 104.16–104.31 (the old 1[6-9]|2[0-1] stopped at
# .21, so 104.22–104.31 edge IPs leaked through as false "origin" bridges); 172.64.0.0/13 = .64–.71.
CDN = re.compile(r"^(104\.(1[6-9]|2[0-9]|3[01])\.|172\.(6[4-9]|7[0-1])\.|188\.114\.9[67]\.|162\.159\.|173\.245\.|103\.21\.24|141\.101\.)")
PRIVACY_EMAIL = re.compile(r"(abuse|privacy|whois|redacted|withheld|proxy|protect|registrar|domainsbyproxy|namecheap|hostinger|gname|dynadot)", re.I)

def load(fp):
    try: return json.load(open(fp))
    except Exception: return None

def flat_pivots(d):
    out=defaultdict(list)
    for p in d.get("pivots",[]):
        if isinstance(p,dict) and "kind" in p:
            out[p["kind"]].append(p.get("value"))
    return out

rows=[]
shared=defaultdict(set)          # (artifact_kind, value) -> {hosts}
apps=[]
for fp in sorted(glob.glob(f"{RAW}/*.json")):
    d=load(fp)
    if not d: continue
    a=d.get("artifacts",{}); meta=d.get("meta",{}); piv=flat_pivots(d)
    host=meta.get("host") or os.path.basename(fp)[:-5]
    w=a.get("whois",{}) or {}
    tls=a.get("tls_cert") or {}
    trackers=a.get("trackers",{}) or {}
    saas=a.get("saas_ids",{}) or {}
    verif=a.get("verifications",{}) or {}
    crypto=a.get("crypto",{}) or {}
    socials=a.get("socials",{}) or {}
    appd=a.get("app_downloads",{}) or {}
    # collect app download urls
    def urls(x):
        u=[]
        if isinstance(x,dict):
            for v in x.values(): u+=urls(v)
        elif isinstance(x,list):
            for v in x: u+=urls(v)
        elif isinstance(x,str) and x.startswith("http"): u.append(x)
        return u
    aurls=urls(appd)
    for u in aurls: apps.append((host,u))

    # origin candidates = non-CDN IPs from crtsh/passivedns/fofa pivots
    origins=set()
    for k,vals in piv.items():
        if any(t in k for t in ("passivedns","crtsh","fofa","origin","dns:a","ip")):
            for v in vals:
                m=re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(v))
                for ip in m:
                    if not CDN.match(ip): origins.add(ip)
    # strong shared artifacts
    if tls.get("fingerprint_sha256"): shared[("tls_sha256",tls["fingerprint_sha256"])].add(host)
    if a.get("dom_skeleton_sha1"): shared[("dom_skeleton",a["dom_skeleton_sha1"])].add(host)
    for gid in list(trackers.values())+list(saas.values())+list(verif.values()):
        for v in (gid if isinstance(gid,list) else [gid]):
            if v and re.match(r"(G-|UA-|GTM-|AW-)",str(v)): shared[("ga_gtm",str(v))].add(host)
    for wl in urls(crypto) if isinstance(crypto,dict) else []:
        pass
    def wallets(x):
        out=[]
        if isinstance(x,dict):
            for v in x.values(): out+=wallets(v)
        elif isinstance(x,list):
            for v in x: out+=wallets(v)
        elif isinstance(x,str) and len(x)>=26: out.append(x)
        return out
    for wl in wallets(crypto): shared[("wallet",wl)].add(host)
    email=w.get("registrant_email")
    if email and not PRIVACY_EMAIL.search(email): shared[("registrant_email",email)].add(host)
    phone=w.get("registrant_phone")
    if phone: shared[("registrant_phone",str(phone))].add(host)
    for oi in origins: shared[("origin_ip",oi)].add(host)

    rows.append(dict(
        host=host, final_url=meta.get("final_url",""),
        fetched=meta.get("fetched_with",""), wayback=meta.get("archived_via_wayback",""),
        title=(a.get("title") or "")[:60],
        tech=";".join(a.get("tech_fingerprint",[])[:3]),
        server=(a.get("server_headers",{}) or {}).get("server",""),
        tls_sha256=tls.get("fingerprint_sha256",""),
        tls_sans=";".join(tls.get("sans",[])[:6]),
        dom_skeleton=a.get("dom_skeleton_sha1",""),
        ga_gtm=";".join(sorted({str(v) for grp in (trackers,saas,verif) for vv in grp.values() for v in (vv if isinstance(vv,list) else [vv]) if v and re.match(r'(G-|UA-|GTM-|AW-)',str(v))})),
        wallets=";".join(sorted(set(wallets(crypto)))),
        emails=";".join(a.get("emails",[])[:4]),
        telegram=";".join(socials.get("telegram",[])[:3]) if isinstance(socials,dict) else "",
        registrant_email=email or "", registrant_name=w.get("registrant_name") or "",
        registrant_phone=phone or "", registrant_address=(w.get("registrant_address") or "")[:60],
        registrant_org=w.get("registrant_org") or "", registrar=w.get("registrar") or "",
        created=w.get("created") or "", ns=";".join((w.get("name_servers") or [])[:4]),
        origin_candidates=";".join(sorted(origins)),
        app_downloads=";".join(u for _,u in [(host,x) for x in aurls]),
        history_err=(w.get("history",{}) or {}).get("error",""),
    ))

# write enriched CSV
cols=["host","final_url","fetched","wayback","title","tech","server","tls_sha256","tls_sans",
      "dom_skeleton","ga_gtm","wallets","emails","telegram","registrant_email","registrant_name",
      "registrant_phone","registrant_address","registrant_org","registrar","created","ns",
      "origin_candidates","app_downloads","history_err"]
with open(f"{OUTD}/enriched_pivots.csv","w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=cols); w.writeheader()
    for r in sorted(rows,key=lambda r:r["host"]): w.writerow(r)

# shared-artifact bridge report (>=2 hosts)
with open(f"{OUTD}/shared_pivots.md","w") as f:
    f.write("# Shared strong artifacts — same-operator bridges (>=2 hosts)\n\n")
    f.write(f"_{len(rows)} hosts enriched. Below: every attribution-grade/corroborating artifact shared by 2+ hosts._\n\n")
    order={"registrant_email":0,"registrant_phone":1,"wallet":2,"ga_gtm":3,"tls_sha256":4,"dom_skeleton":5,"origin_ip":6}
    items=[(k,v,hs) for (k,v),hs in shared.items() if len(hs)>=2]
    items.sort(key=lambda x:(order.get(x[0],9), -len(x[2])))
    if not items: f.write("_(none yet — run after enrichment completes)_\n")
    for k,v,hs in items:
        f.write(f"- **{k}** = `{v}`  ({len(hs)} hosts)\n")
        f.write(f"    - {', '.join(sorted(hs))}\n")

# app downloads
with open(f"{OUTD}/app_downloads.txt","w") as f:
    for host,u in apps: f.write(f"{host}\t{u}\n")

print(f"hosts: {len(rows)}")
print(f"shared strong artifacts (>=2 hosts): {sum(1 for (k,v),hs in shared.items() if len(hs)>=2)}")
print(f"app-download URLs: {len(apps)}")
print(f"-> {OUTD}/enriched_pivots.csv | shared_pivots.md | app_downloads.txt")
