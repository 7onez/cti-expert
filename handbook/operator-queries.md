# Operator Queries

Search engine operator patterns for open-source discovery. Organized by subject type.

---

## Operator Reference

| Operator | Function | Example |
|----------|----------|---------|
| `"phrase"` | Exact match | `"jane smith" "acme corp"` |
| `site:` | Restrict to domain | `site:github.com` |
| `filetype:` | File extension filter | `filetype:pdf` |
| `inurl:` | Text in URL | `inurl:admin` |
| `intitle:` | Text in page title | `intitle:"index of"` |
| `intext:` | Text in body | `intext:password` |
| `-` | Exclude term | `-site:pinterest.com` |
| `OR` | Either term | `site:x.com OR site:twitter.com` |
| `*` | Wildcard | `"john * smith"` |
| `after:` | Published after date | `after:2025-01-01` |
| `before:` | Published before date | `before:2024-06-01` |
| `cache:` | Cached version | `cache:example.com` |

Combine 2–4 operators per query. More operators = higher precision, fewer results.

---

## Domain / Infrastructure Queries

**Exposed files:**
```
site:TARGET filetype:pdf
site:TARGET filetype:env OR filetype:log OR filetype:sql
site:TARGET filetype:xlsx OR filetype:csv
site:TARGET intitle:"index of /" "parent directory"
```

**Admin panels:**
```
site:TARGET inurl:admin OR inurl:dashboard OR inurl:cpanel
site:TARGET inurl:login OR inurl:signin OR inurl:wp-admin
```

**API and dev artifacts:**
```
site:TARGET inurl:api OR inurl:graphql OR inurl:swagger
site:TARGET inurl:staging OR inurl:dev OR inurl:test
site:TARGET filetype:yaml OR filetype:yml
```

**Third-party references:**
```
"TARGET-DOMAIN" site:github.com
"TARGET-DOMAIN" site:pastebin.com
"TARGET-DOMAIN" site:trello.com OR site:notion.so
```

---

## Person / Identity Queries

**Core identity sweep:**
```
"Full Name"
"Full Name" site:linkedin.com
"Full Name" + "City" OR "Employer"
"Full Name" filetype:pdf
```

**Contact discovery:**
```
"firstname.lastname" "@domain.com"
"first last" "phone" OR "mobile" OR "contact"
"Full Name" inurl:contact OR inurl:about
```

**Professional presence:**
```
"Full Name" site:scholar.google.com
"Full Name" site:researchgate.net
"Full Name" patent
"Full Name" site:sec.gov
```

---

## Credential / Exposure Queries

**Leaked data indicators:**
```
"@target-domain.com" site:pastebin.com
"@target-domain.com" site:ghostbin.com
"target-domain.com" "password" OR "passwd"
"target-domain.com" "API key" OR "api_key" OR "secret"
```

**Code repository exposure:**
```
site:github.com "target-domain.com" "password"
site:github.com "target-domain.com" extension:env
site:github.com "target-domain.com" "BEGIN RSA PRIVATE KEY"
```

---

## Legal and Financial Queries

**Court and regulatory:**
```
"Full Name" site:courtlistener.com
"Company Name" site:sec.gov 10-K OR 10-Q
"Company Name" site:pacer.gov
"Full Name" OR "Company Name" "judgment" OR "lawsuit"
```

**Property and business:**
```
"Full Name" "property" site:[state-assessor-domain]
"Company Name" site:opencorporates.com
"Company Name" "annual report" filetype:pdf
```

---

## Social Media Queries

**Profile discovery:**
```
"username" site:x.com OR site:twitter.com
"username" site:reddit.com
"username" site:instagram.com
"username" site:github.com
"Full Name" site:facebook.com
```

**Content sweep:**
```
"username" OR "Full Name" inurl:posts OR inurl:status
"handle" "city" OR "location"
"handle" after:2024-01-01
```

**Noise reduction** — strip common false-positive domains:
```
"Full Name" -site:pinterest.com -site:yellowpages.com -site:whitepages.com -site:spokeo.com
```

---

## Cross-Platform Mega-Dorks

Single queries hitting multiple platforms at once. Replace `TARGET` with name, username, email, domain, or phone number.

**All major social media (single query):**
```
"TARGET" (site:facebook.com OR site:x.com OR site:twitter.com OR site:instagram.com OR site:youtube.com OR site:tiktok.com OR site:linkedin.com OR site:reddit.com OR site:threads.net)
```

**Telegram ecosystem (all Telegram-related domains):**
```
"TARGET" (site:t.me OR site:telegram.org OR site:telegram.me OR site:tgstat.com OR site:telemetr.io OR site:telemetryapp.io OR site:tgstat.ru OR site:telemetr.me OR site:telegra.ph OR site:storebot.me OR site:tlgrm.eu OR site:telegramchannels.me OR site:telegram-group.com)
```

**Developer/code platforms:**
```
"TARGET" (site:github.com OR site:gitlab.com OR site:bitbucket.org OR site:stackoverflow.com OR site:npmjs.com OR site:pypi.org OR site:hub.docker.com OR site:codeberg.org)
```

**Forums and communities:**
```
"TARGET" (site:reddit.com OR site:quora.com OR site:stackexchange.com OR site:medium.com OR site:substack.com OR site:hackernews.com OR site:news.ycombinator.com OR site:discord.com)
```

**Paste sites and dumps:**
```
"TARGET" (site:pastebin.com OR site:ghostbin.com OR site:paste.org OR site:dpaste.com OR site:hastebin.com OR site:justpaste.it OR site:rentry.co OR site:privatebin.net)
```

**Darknet-adjacent and leak sites:**
```
"TARGET" (site:ddosecrets.com OR site:wikileaks.org OR site:cryptome.org OR site:ransomwatch.telemetry.ltd OR site:ransomware.live)
```

**Breach and credential databases:**
```
"TARGET" (site:haveibeenpwned.com OR site:dehashed.com OR site:leakcheck.io OR site:breachdirectory.org OR site:intelx.io)
```

**Business and corporate intel:**
```
"TARGET" (site:opencorporates.com OR site:crunchbase.com OR site:dnb.com OR site:glassdoor.com OR site:bbb.org OR site:sec.gov OR site:courtlistener.com)
```

**Image and visual search:**
```
"TARGET" (site:flickr.com OR site:500px.com OR site:deviantart.com OR site:imgur.com OR site:unsplash.com OR site:pinterest.com)
```

**Messaging and chat platforms:**
```
"TARGET" (site:discord.com OR site:slack.com OR site:keybase.io OR site:matrix.org OR site:signal.group OR site:whatsapp.com)
```

**Job and recruitment (identity pivot):**
```
"TARGET" (site:linkedin.com OR site:indeed.com OR site:glassdoor.com OR site:angel.co OR site:wellfound.com OR site:hired.com)
```

### Usage Tips

- Replace `TARGET` with any identifier: `"john.doe"`, `"john@example.com"`, `"+1234567890"`, `"example.com"`
- Add `after:YYYY-MM-DD` to time-bound results
- Add `-site:unwanted.com` to exclude noisy domains
- Google limits `OR` chains to ~32 terms — split into multiple queries if needed
- For organization investigations, combine: `"Company Name" OR "company.com" (site:...)`
- Wrap multi-word targets in quotes: `"Jane Smith"` not `Jane Smith`

*See also: [`handbook/quick-report.md`](./quick-report.md)*
