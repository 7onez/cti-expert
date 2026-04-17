---
phase: 1
priority: high
status: completed
---

# Phase 1 — Universal WHOIS for All TLDs

## Overview

Replace the basic `whois` CLI approach with a multi-layer WHOIS cascade supporting ALL TLDs including ccTLDs like .vn, .th, .sg, .kr. Zero API auth required for core functionality.

## Key Insights

- `whoisdomain` Python library covers ~90% of TLDs via IANA auto-detection
- `.vn` WHOIS server is `whois.vnnic.vn` (port 43), operated by VNNIC
- `whois-server-list` GitHub project maintains weekly-updated TLD→server JSON mapping
- Free web APIs: Whoxy (1595+ TLDs, 100% free), WhoisJSON (1500+ TLDs, 1K req/mo free)
- Reverse WHOIS free alternatives exist (Whoxy reverse API, ViewDNS reverse)

## Files to Modify

| File | Action | What Changes |
|------|--------|-------------|
| `techniques/whois-universal.md` | **CREATE** | New technique file with universal WHOIS cascade |
| `techniques/web-dns-forensics.md` | EDIT | Replace Section 9 with pointer to new file |
| `handbook/tool-cascade-reference.md` | EDIT | Add WHOIS cascade table |

## Implementation Steps

### 1. Create `techniques/whois-universal.md`

New technique file (~180 lines) covering:

```markdown
# Universal WHOIS Investigation

## 1. Overview
Multi-TLD WHOIS with 4-layer fallback cascade. Covers gTLDs, ccTLDs (.vn, .th, .sg, .kr, etc.), 
and IP/ASN lookups. Zero API keys for core functionality.

## 2. WHOIS Cascade

### Layer 1: whoisdomain Python library (Primary)
- Auto-detects TLD → correct WHOIS server via IANA
- ~90% coverage, parsed structured output
- Install: `pip3 install whoisdomain`
- Usage: `python3 -c "import whoisdomain; print(whoisdomain.query('example.vn'))"` 

### Layer 2: CLI whois with TLD-specific server (Secondary)
- Direct server specification for ccTLDs
- Key ccTLD servers table:
  | TLD | WHOIS Server |
  |-----|-------------|
  | .vn | whois.vnnic.vn |
  | .th | whois.thnic.co.th |
  | .sg | whois.sgnic.sg |
  | .kr | whois.kr |
  | .jp | whois.jprs.jp |
  | .cn | whois.cnnic.cn |
  | .tw | whois.twnic.net.tw |
  | .id | whois.id |
  | .my | whois.mynic.my |
  | .ph | whois.dot.ph |
  | .in | whois.registry.in |
  | .ru | whois.tcinet.ru |
  | .br | whois.registro.br |
  | .za | whois.registry.net.za |
  | .ng | whois.nic.net.ng |
  | .ke | whois.kenic.or.ke |
  | .de | whois.denic.de |
  | .fr | whois.nic.fr |
  | .it | whois.nic.it |
  | .es | whois.nic.es |
  | .nl | whois.sidn.nl |
  | .uk | whois.nic.uk |
  | .au | whois.auda.org.au |
  | .nz | whois.srs.net.nz |

- Usage: `whois -h whois.vnnic.vn domain.vn`

### Layer 3: Whoxy Free API (Tertiary)  
- 1595+ TLD coverage, JSON response
- No auth, no rate limits published
- `curl -s "https://api.whoxy.com/?key=free&whois=domain.vn"`
- Also supports: reverse WHOIS, WHOIS history

### Layer 4: Web scrape fallback (Quaternary)
- who.is web UI → parse HTML
- WebSearch: `"domain.vn" whois registration`

## 3. Reverse WHOIS (Free)
- Whoxy reverse: `https://api.whoxy.com/?key=free&reverse=whois&name=John+Doe`
- ViewDNS reverse: WebSearch `site:viewdns.info/reversewhois/?q=email@domain.com`
- DomainBigData: WebSearch `site:domainbigdata.com "registrant" "target@email.com"`

## 4. Historical WHOIS (Free)
- Whoxy history: `https://api.whoxy.com/?key=free&history=domain.com`
- WebSearch: `site:web.archive.org "domain.com" whois`
- Google cache of SecurityTrails/DomainTools pages

## 5. IP/ASN WHOIS
(existing content from web-dns-forensics.md Section 9)

## 6. .vn Domain WHOIS Deep Dive
- Server: whois.vnnic.vn (port 43)
- Operator: VNNIC (Vietnam Internet Network Information Center)
- Web interface: https://vnnic.vn/en/whois-information
- Response fields: registrant, admin contact, tech contact, name servers, dates
- Parsing notes: Vietnamese text in registrant fields common; UTF-8 encoding
- No REST API available; port 43 or web scrape only

## 7. Investigation Workflow
Step 1: whoisdomain query → if structured result, DONE
Step 2: If parse fails → CLI whois -h <tld-server> → raw text
Step 3: If connection refused → Whoxy API → JSON
Step 4: If all fail → web scrape who.is → HTML parse
Step 5: Cross-reference with DNS history for timeline

## 8. Confidence Ratings
| Source | Confidence | Notes |
|--------|-----------|-------|
| whoisdomain parsed | HIGH | Direct WHOIS server query |
| CLI whois raw | HIGH | Authoritative server |  
| Whoxy API | MEDIUM | Third-party aggregator |
| Web scrape | LOW | May be cached/stale |
```

### 2. Update `techniques/web-dns-forensics.md` Section 9

Replace the current basic WHOIS section with a cross-reference:

```markdown
## 9. WHOIS Deep Investigation

> **Moved to dedicated module:** See `techniques/whois-universal.md` for the full 
> multi-TLD WHOIS cascade with support for all ccTLDs (.vn, .th, .sg, .kr, etc.),
> reverse WHOIS, historical WHOIS, and IP/ASN lookups — all free, no API keys.
```

### 3. Add WHOIS cascade to `handbook/tool-cascade-reference.md`

Add new section after existing cascades:

```markdown
### WHOIS / Domain Registration

| Priority | Tool | Method | Notes |
|----------|------|--------|-------|
| 1 (Primary) | whoisdomain | `python3 -c "import whoisdomain; print(whoisdomain.query('<domain>'))"` | IANA auto-detect, ~90% TLDs |
| 2 (Secondary) | CLI whois | `whois -h <tld-server> <domain>` | Direct ccTLD server query |
| 3 (Tertiary) | Whoxy API | `curl "https://api.whoxy.com/?key=free&whois=<domain>"` | 1595+ TLDs, free |
| 4 (Quaternary) | who.is web | `who.is/whois/<domain>` | Web UI, manual or scrape |
| 5 (Reverse) | Whoxy reverse | `curl "https://api.whoxy.com/?key=free&reverse=whois&email=<email>"` | Free reverse WHOIS |
```

## Todo List

- [ ] Create `techniques/whois-universal.md` (~180 lines)
- [ ] Replace Section 9 of `techniques/web-dns-forensics.md` with cross-reference
- [ ] Add WHOIS cascade to `handbook/tool-cascade-reference.md`
- [ ] Verify ccTLD server list completeness (25+ servers)

## Success Criteria

- WHOIS works for .vn, .th, .sg, .kr, .jp, .cn + all common gTLDs
- 4-layer fallback cascade documented
- Reverse WHOIS has free alternatives
- .vn-specific deep dive with VNNIC details
