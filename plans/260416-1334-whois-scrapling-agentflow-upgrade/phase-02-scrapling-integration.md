---
phase: 2
priority: high
status: completed
---

# Phase 2 — Scrapling Web Collection + Headless Browser Auto-Open

## Overview

Integrate Scrapling as the middle-tier web collection engine between WebFetch (lightweight) and agent-browser (Playwright full). Make headless browser the DEFAULT for JS-heavy sites. Three-tier fetcher cascade maps to CTI collection needs.

## Key Insights

- Scrapling has 3 fetcher classes: Fetcher (static), StealthyFetcher (anti-bot), DynamicFetcher (JS)
- Base install is lightweight (`pip install scrapling`); headless browser optional (`scrapling[fetchers]`)
- 37k GitHub stars, active maintenance, Python 3.10+
- HTML parsing ~1.99ms vs BeautifulSoup 1,541ms — massive speed improvement
- DynamicFetcher wraps Playwright internally — complements, doesn't conflict with agent-browser
- Adaptive selectors auto-relocate when site structure changes — critical for OSINT durability

## Files to Modify

| File | Action | What Changes |
|------|--------|-------------|
| `techniques/web-collection-scrapling.md` | **CREATE** | New technique for Scrapling-based web collection |
| `SKILL.md` | EDIT | Update Tool Priority & Fallback section |
| `handbook/tool-cascade-reference.md` | EDIT | Add Web Collection cascade |
| `techniques/scam-check.md` | EDIT | Reference Scrapling for scrape-heavy steps |

## Implementation Steps

### 1. Create `techniques/web-collection-scrapling.md`

New technique file (~180 lines):

```markdown
# Web Collection via Scrapling

## 1. Overview
Scrapling provides adaptive, resilient web data collection for OSINT. 
Three fetcher tiers auto-escalate based on site behavior.
Headless browser opens BY DEFAULT for JS-heavy targets.

## 2. Collection Cascade

### Tier 1: Fetcher (Fast Static)
- For: Static HTML pages, APIs returning HTML/JSON, simple forms
- Speed: ~2ms parse time
- Install: `pip3 install scrapling` (base, no browser)

Usage:
  from scrapling.fetchers import Fetcher
  page = Fetcher.get('https://who.is/whois/example.com')
  registrant = page.css('.whois-data .registrant').text

### Tier 2: StealthyFetcher (Anti-Bot Bypass)
- For: Cloudflare-protected sites, rate-limited services, bot-detection pages
- Method: Playwright + fingerprint spoofing
- Install: `pip3 install "scrapling[fetchers]" && scrapling install`

Usage:
  from scrapling.fetchers import StealthyFetcher
  page = StealthyFetcher.get('https://cloudflare-protected-osint.com')
  data = page.css('.results').text

### Tier 3: DynamicFetcher (JavaScript Rendering) — DEFAULT for JS sites
- For: React/Vue/Angular SPAs, infinite scroll, client-rendered content
- Method: Full Playwright browser with JS execution
- **THIS IS THE DEFAULT** when target is detected as JS-heavy

Usage:
  from scrapling.fetchers import DynamicFetcher
  page = DynamicFetcher.get('https://react-osint-tool.com')
  results = page.css('.dynamic-content').getall()

## 3. Auto-Escalation Logic

When collecting data from a URL:
1. Try Fetcher.get(url) — if response has content, use it
2. If 403/429/captcha detected → escalate to StealthyFetcher
3. If content empty or JS-placeholder detected → escalate to DynamicFetcher
4. If all fail → fall back to WebFetch/WebSearch
5. Tag finding: [scrapling-static] / [scrapling-stealth] / [scrapling-dynamic]

## 4. Headless Browser Auto-Open Policy

DEFAULT BEHAVIOR: When a URL is fetched during investigation:
- Static content (HTML with data) → Fetcher (no browser)
- 403/bot-block → StealthyFetcher (headless browser, stealth mode)
- JS-heavy/SPA detected → DynamicFetcher (headless browser, full render)
- Screenshot needed → agent-browser (Playwright direct)

Detection heuristic for JS-heavy:
- Response body contains <div id="root"></div> or <div id="app"></div> with no content
- Response body < 1KB but Content-Length header suggests larger page
- Known JS-heavy domains: social media, modern OSINT tools, dashboards

## 5. Session Management

For multi-page collection (e.g., paginated results):
  from scrapling.fetchers import StealthyFetcher
  session = StealthyFetcher()
  page1 = session.get('https://target.com/results?page=1')
  page2 = session.get('https://target.com/results?page=2')
  # Cookies persist across requests

## 6. Integration with Existing Techniques

Scrapling enhances these techniques:
- scam-check.md: Steps 2-7 (scraping PhishTank, CheckPhish, etc.)
- phone-osint.md: USPhoneBook scraping (currently uses cloudscraper)
- fx-visitor-intelligence.md: SimilarWeb data extraction
- image-forensics: FaceCheck.id result scraping
- social-media-platforms.md: Profile data extraction

## 7. Fallback Cascade (Full)

agent-browser (Playwright) → DynamicFetcher → StealthyFetcher → Fetcher → WebFetch → WebSearch → curl

## 8. Confidence Ratings
| Collection Method | Tag | Confidence |
|-------------------|-----|-----------|
| Scrapling Fetcher | [scrapling-static] | HIGH |
| Scrapling StealthyFetcher | [scrapling-stealth] | HIGH |
| Scrapling DynamicFetcher | [scrapling-dynamic] | HIGH |
| WebFetch | [fetch] | MEDIUM |
| WebSearch | [search] | MEDIUM |
```

### 2. Update SKILL.md Tool Priority & Fallback

Replace current section (lines ~781-786):

```markdown
## Tool Priority & Fallback

1. Check `agent-browser` availability first
2. Use `agent-browser` for: screenshot evidence, interactive UI, complex multi-step browser flows
3. Use Scrapling DynamicFetcher for: JS-heavy sites, SPA content, auto-escalation from static
4. Use Scrapling StealthyFetcher for: anti-bot bypass, Cloudflare-protected targets
5. Use Scrapling Fetcher for: fast static page collection, HTML parsing
6. Fall back to web search → web fetch → direct curl — no investigation blockers
7. Tag each finding with collection method: `[browser]` · `[scrapling-dynamic]` · `[scrapling-stealth]` · `[scrapling-static]` · `[search]` · `[fetch]` · `[manual]`
```

### 3. Add Web Collection cascade to `handbook/tool-cascade-reference.md`

```markdown
### Web Collection / Page Fetching

| Priority | Tool | Method | Notes |
|----------|------|--------|-------|
| 1 (Screenshots) | agent-browser | Playwright full automation | Interactive, visual evidence |
| 2 (JS-heavy) | Scrapling DynamicFetcher | `DynamicFetcher.get(url)` | Playwright-backed, JS rendering |
| 3 (Anti-bot) | Scrapling StealthyFetcher | `StealthyFetcher.get(url)` | Cloudflare bypass, fingerprint spoofing |
| 4 (Fast static) | Scrapling Fetcher | `Fetcher.get(url)` | ~2ms parse, adaptive selectors |
| 5 (CLI) | WebFetch | Claude tool | Built-in, no deps |
| 6 (Search) | WebSearch | Claude tool | Google results only |
| 7 (Raw) | curl | `curl -sL url` | Last resort |
```

### 4. Update `techniques/scam-check.md`

Add note at top of file referencing Scrapling for web scraping steps:

```markdown
> **Collection method:** Steps that scrape web pages use Scrapling fetchers 
> (see `techniques/web-collection-scrapling.md`). Auto-escalates from 
> static → stealth → dynamic based on target response.
```

## Todo List

- [ ] Create `techniques/web-collection-scrapling.md` (~180 lines)
- [ ] Update SKILL.md Tool Priority & Fallback section
- [ ] Add Web Collection cascade to tool-cascade-reference.md
- [ ] Add Scrapling reference to scam-check.md
- [ ] Verify Scrapling import patterns are correct

## Success Criteria

- Scrapling 3-tier fetcher documented with code examples
- Tool priority chain updated: agent-browser → Scrapling → WebFetch → WebSearch
- Headless browser auto-open documented as default for JS-heavy sites
- Collection method tags expanded to include Scrapling variants
