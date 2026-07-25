# China / Sinophone Recon — ICP filings, PRC corporate registries, CN cyberspace engines

Attribution layer for **Chinese-operated infrastructure**: map a domain to its PRC filing and
registered company, resolve that company's real structure through state and commercial
registries, search the three Chinese cyberspace engines, and generate the CJK/pinyin name
variants Western tooling misses.

> **Why this matters here.** A large share of SEA scam, gambling, and fraud infrastructure is
> Chinese-operated. The **ICP filing** is a hard domain→company link, and an ICP *license
> number* is a same-operator pivot as strong as a shared GA ID — one filing routinely covers
> dozens of domains. Neither is reachable through Western registries.

Feeds `/webpivot`, `/cn-corp`, `/pivot-suggest`, `/exposure`, `/threat-model`, `/report ioc`.

---

## 1. ICP filing (工信部备案) — the domain→company link

Every domain legally served from mainland China needs an **ICP filing** with MIIT. The filing
binds the domain to a **registered entity** (company or individual) and issues a licence number.

### Licence number grammar

```
苏ICP备12345678号-3
│  │      │        └─ per-site sequence under the same filing
│  │      └────────── filing serial (the operator-level key)
│  └───────────────── 备 = filed;  ICP备 = ICP filing,  网安备 = MPS public-security filing
└──────────────────── province abbreviation (苏 Jiangsu, 粤 Guangdong, 浙 Zhejiang, 京 Beijing,
                      沪 Shanghai, 闽 Fujian, 鲁 Shandong, 川 Sichuan, 桂 Guangxi …)
```

`京ICP证` (证 not 备) = a *licence* for commercial services, a stronger signal than a plain filing.
`-1`, `-2`, `-3` suffixes are **sibling sites under one filing** — enumerate them all.

### Where to read it

| Source | What it gives | Notes |
|---|---|---|
| **The page footer itself** | licence number, often the company name | Free, no auth. Extracted automatically — see §1.1 |
| **beian.miit.gov.cn** | authoritative: entity name, entity type, licence, approval date | Free; CAPTCHA; Chinese-only; rate-limited |
| **ICP_Query** (`icp-query`) | scripted domain→filing lookup | Community tool; wraps third-party mirrors — verify hits against MIIT |
| **beian.xiaomo / chinaz / aizhan ICP mirrors** | cached filing records, sometimes historical | Mirrors go stale; treat as ANECDOTAL (2) until MIIT-confirmed |
| **ENScan_GO** (`enscan -n "<公司全名>"`) | company → ICP filings + domains + apps + mini-programs | Needs aggregator cookies in YAML config |

### 1.1 Extract from the live/archived page first (keyless)

The footer is usually enough to seed the pivot, and it works on archived copies of infra that
is now dark:

```bash
# ICP licence numbers + MPS filings in a page (live or Wayback-fetched).
# -P for \p{Han}; ripgrep understands the same class: rg -o '\p{Han}?ICP[备证]…'
grep -oP '\p{Han}?ICP[备证]\d{5,10}号(-\d{1,3})?' page.html
grep -oP '\p{Han}{2,}公安(网)?备\d{8,}号?' page.html
```

If neither `grep -P` nor `rg` is available (macOS BSD grep), match the literal filing marker —
CJK literals work in plain ERE — then read the province prefix from the surrounding text:

```bash
grep -oE 'ICP(备|证)[0-9]{5,10}号(-[0-9]{1,3})?' page.html
```

Prefer the archived copy for hostile infrastructure (`wayback_fetch.py`) — filings are often
scrubbed from the live site *after* a network is reported, but persist in snapshots.

### 1.2 The ICP pivot (the high-value move)

```
domain ──▶ ICP licence  ──▶ [ same serial ] ──▶ sibling domains  (same operator, HIGH confidence)
                        └──▶ registered company ──▶ §2 registry chain ──▶ officers, subsidiaries, UBO
```

Reverse-lookup a licence serial:

| Method | Query |
|---|---|
| Source search | PublicWWW / NerdyData: `"苏ICP备12345678号"` |
| urlscan | `page.content:"ICP备12345678"` (PRO for content search) |
| Site-restricted dork | `"ICP备12345678号" -site:beian.miit.gov.cn` |
| FOFA | `body="ICP备12345678"` |
| Quake / ZoomEye | full-text body search on the licence string |
| ENScan_GO | `enscan -n "<company>"` → all filings held by that entity |

**Confidence:** shared licence **serial** = same registrant → treat as **HIGH (85)**, same tier as
a shared registrant email. Shared *province prefix only* is worthless — do not cluster on it.

---

## 2. PRC corporate registry chain

Anchor on the **中文 legal name** or the **USCC** (统一社会信用代码, 18 chars) — never an English
trade name, which is usually unregistered marketing.

```
USCC / 中文全名
   │
   ├─▶ GSXT ................. ground truth (state registry)      ── verify existence + status
   ├─▶ TianYanCha/QCC/Aiqicha relational enrichment              ── officers, shareholders, branches
   ├─▶ Cninfo ............... filings (listed companies only)    ── audited ownership
   ├─▶ 信用中国 ............. credit + blacklist (失信) status
   └─▶ Sayari / Datenna ..... cross-border UBO + sanctions
```

| Source | URL | Access reality |
|---|---|---|
| **GSXT** 国家企业信用信息公示系统 | `gsxt.gov.cn` | **Authoritative.** Free. Chinese-only, heavy CAPTCHA (slider). Registration no., legal rep, capital, status, address |
| **信用中国** | `creditchina.gov.cn` | Free. Administrative penalties, 失信 (dishonest-entity) listings |
| **TianYanCha** 天眼查 | `tianyancha.com` | **IP-blocked outside mainland since ~2022.** Needs CN egress + +86 account. Best relational graph (shareholders, related firms) |
| **QCC** 企查查 | `qcc.com` | Same constraints. Good branch/change history |
| **Aiqicha** 爱企查 (Baidu) | `aiqicha.baidu.com` | Same constraints. Often the most permissive of the three |
| **Cninfo** 巨潮资讯 | `cninfo.com.cn` | Free. Official filings for **listed** companies only |
| **HKGRD** (HK companies) | `mmo.icris.cy.gov.hk` | Paid per-search. Common for the offshore holding layer |
| **Sayari / Datenna** | commercial | Cross-border UBO, sanctions, subsidiary trees. Paid |

### USCC (统一社会信用代码) sanity check

18 characters: `[registering authority 1][entity type 1][admin division 6][org code 9][check 1]`.
Positions 3–8 are a **GB/T 2260 division code** — the registering locality, a geographic lead
independent of the stated address. Reject a "USCC" that is not 18 chars of `[0-9A-HJ-NPQRTUWXY]`.

### Ownership reading rules

1. **Legal representative ≠ owner.** 法定代表人 is often a nominee. Read 股东 (shareholders).
2. **Follow the holding chain.** PRC scam structures nest 3–5 deep, frequently via HK or a
   free-trade-zone shell. Recurse until you reach a natural person or a foreign entity.
3. **Registered capital 认缴 vs 实缴.** Subscribed ≠ paid-in. A ¥10M "capital" company with
   ¥0 paid-in is a shell.
4. **Status matters.** 吊销 (revoked) / 注销 (deregistered) with a live website = strong fraud
   indicator → promote to a HIGH finding.
5. **Address reuse.** One registered address across many unrelated firms = incorporation-agent
   farm. Cluster, but do not treat as same-operator on its own (MEDIUM at best).

---

## 3. CN cyberspace engines

Three independent indexes of Chinese-visible infrastructure, all with materially different
coverage from Shodan/Censys. Add keys via `/apikeys`; all have free tiers.

| Engine | CLI | Syntax sample | Notes |
|---|---|---|---|
| **FOFA** | `fofax -q '<query>'` · `fofa-py` | `domain="example.com"`, `icon_hash="-247388890"`, `body="ICP备123"` | Best CN asset coverage. Already wired into `/webpivot` |
| **Quake (360)** | `quake init <key>` → `quake search '<query>'` | `domain:"example.com"`, `favicon:"<hash>"`, `body:"ICP备123"` | **Independent index** — routinely finds hosts FOFA misses |
| **ZoomEye** | `zoomeye search '<query>'` · `kunyu console` | `iconhash:"<mmh3>"`, `site:example.com` | Kunyu = friendlier ZoomEye console |

**Favicon hash algorithm per engine** — Shodan / FOFA / ZoomEye / Quake use **mmh3**, Censys
MD5, Netlas SHA-256. `pivot_extract.py` already emits all three; pick the right one.

Run these **in addition to**, not instead of, Shodan/Censys — the point is index diversity.

---

## 4. Baidu / Sogou dorking

`/dork-sweep` cascades Google→Bing→DDG→agent-browser and therefore **misses Chinese-indexed
content entirely**. Add a Baidu tier for CJK targets.

```bash
uv tool install pydork
pydork search -t baidu -- '"关键词" site:example.com'
```

| Operator | Baidu behaviour |
|---|---|
| `site:` | supported |
| `inurl:` / `intitle:` | supported |
| `filetype:` | supported, narrower corpus than Google |
| `-term` | supported |
| `""` | weaker phrase-binding than Google — verify hits manually |

Baidu ranks CN-hosted and ICP-filed content far higher; **Sogou** (`weixin.sogou.com`) is the
only practical browser route into **WeChat 公众号** articles.

---

## 5. CJK identity variants — the transliteration pivot

A Chinese operator name has **multiple valid Latin forms**, plus Simplified and Traditional
orthographies. Enumerating one form only finds one slice of the graph. Wired into
`/pivot-suggest` (`detect_cjk_variants`).

Given `张伟`:

| Axis | Variants |
|---|---|
| Pinyin (toneless) | `zhangwei`, `zhang wei`, `zhang-wei`, `zhang_wei` |
| Surname-first / given-first | `zhangwei`, `weizhang` |
| Initials | `zw`, `w.zhang`, `zhang.w` |
| Traditional | `張偉` |
| Wade-Giles / HK-Cantonese / SEA romanizations | `chang wei`, `cheung wai`, `truong` (VN cognate) |

```bash
# romanize + segment (optional deps; the axis degrades gracefully without them)
uv run --with pypinyin python -c "from pypinyin import lazy_pinyin;print(''.join(lazy_pinyin('张伟')))"
# Simplified <-> Traditional
uv run --with opencc-python-reimplemented python -c "import opencc;print(opencc.OpenCC('s2t').convert('张伟'))"
# word segmentation for company-name stems
uv run --with jieba python -c "import jieba;print('/'.join(jieba.cut('深圳市某某科技有限公司')))"
```

**Company-name stems.** Strip the boilerplate before searching: leading locality
(`深圳市`, `北京`), trailing form (`有限公司`, `股份有限公司`, `集团`), and industry filler
(`科技`, `网络`, `信息技术`, `贸易`). What remains is the distinctive stem worth pivoting on.

---

## 6. Chinese social / content platforms

Sinophone platforms are absent from the 3000-platform `/username` enumeration. Check manually
or with a platform tool when a case touches CN-facing operations.

| Platform | Route | Reality |
|---|---|---|
| Weibo 微博 | `s.weibo.com/user?q=<handle>` · `weibo-crawler`, `weiboSpider` | Search partly works logged-out; profiles need login |
| Xiaohongshu 小红书 (RedNote) | `XHS-Downloader` · MediaCrawler | Cookie required |
| Douyin 抖音 | `Douyin_TikTok_Download_API` · MediaCrawler | Cookie required |
| Bilibili | `BBDown`, `you-get` | Public search works logged-out |
| Zhihu 知乎 / Tieba 贴吧 / Kuaishou | MediaCrawler | Cookie required |
| WeChat 公众号 | `we-mp-rss`; browser fallback `weixin.sogou.com` | Account required for the API route |

**MediaCrawler** covers Xiaohongshu/Douyin/Kuaishou/Bilibili/Weibo/Tieba/Zhihu in one tool
(QR login) — prefer it over per-platform scripts when several platforms are in scope.

Reverse image search on Baidu/Sogou has **no reliable CLI** — browser only (`agent-browser`).

---

## 7. Access reality → collection gaps, not blockers

Per the skill's never-block policy, record each unreachable source as a **collection gap** with
its cause, and continue.

| Barrier | Affects | Gap wording |
|---|---|---|
| CN-only egress | TianYanCha, QCC, Aiqicha | `registry unreachable — non-CN egress; GSXT used as substitute` |
| +86 phone / real-name registration | Weibo, Douyin, XHS, WeChat | `platform profile not collected — account gate` |
| CAPTCHA (slider) | GSXT, beian.miit | `filing not MIIT-confirmed — CAPTCHA; mirror record used, trust 2` |
| API key absent | FOFA / Quake / ZoomEye | `CN cyberspace index not queried — no key` |

**OPSEC boundary.** Network-layer localization (CN egress, CN locale) is legitimate tradecraft.
**Identity-layer impersonation is not** — do not register accounts under a real person's
identity documents or phone. PRC real-name registration law tightened in July 2025; using
another person's identity to obtain access is out of scope for OSINT and illegal.

---

## 8. Findings this technique produces

| Finding | Type | Weight | Trust |
|---|---|---|---|
| Domain ICP-filed to `<company>`, licence `<no.>` | `identity` | HIGH | 5 if MIIT-confirmed, 2 if mirror-only |
| N sibling domains share licence serial `<no.>` | `infrastructure` | HIGH | 4 |
| Registered company status 吊销/注销 while site live | `legal` | **CRITICAL** | 5 |
| Shareholder / UBO chain resolved to `<person/entity>` | `identity` | HIGH | 4 |
| Company listed on 信用中国 失信 blacklist | `legal` | HIGH | 5 |
| Registered address shared with N unrelated firms | `behavioral` | MEDIUM | 3 |
| Asset found only in Quake/FOFA, absent from Shodan | `infrastructure` | MEDIUM | 4 |

---

## Cross-references

- [`handbook/pivot-artifacts.md`](../handbook/pivot-artifacts.md) — ICP licence as a pivot artifact
- [`handbook/pivot-services.md`](../handbook/pivot-services.md) — Quake/ZoomEye/FOFA query surfaces
- [`engine/pivot-orchestration.md`](../engine/pivot-orchestration.md) — `icp` / `uscc` / `org` edges
- [`techniques/web-pivot.md`](web-pivot.md) — DOM extraction that yields the licence string
- [`techniques/fx-dork-sweep.md`](fx-dork-sweep.md) — Baidu tier in the dork cascade
- [`scripts/webpivot/pivot_suggest.py`](../scripts/webpivot/pivot_suggest.py) — `detect_cjk_variants`
