# Social Media Platform Techniques Module

> **Module ID:** SMP-001
> **Version:** 1.0.0
> **Phase:** 5 - Enhancement Modules
> **Classification:** Platform-Specific OSINT Techniques

---

## 1. Overview

Platform-specific techniques for extracting intelligence from social media. Covers API endpoints, data artifacts, false positive handling, and cross-platform investigation chains.

---

## 2. Twitter/X Deep Investigation

### 2.1 Persistent Numeric User ID

Every Twitter/X account has a permanent numeric ID that survives username changes:
- Access by ID: `https://x.com/i/user/<numeric_id>`
- Find ID from archived pages (JSON-LD `"author":{"identifier":"..."}`)
- t.co shortlinks point to OLD usernames — the redirect URL contains the username at time of posting

### 2.2 Snowflake Timestamp Decoding

Twitter IDs encode creation timestamps:
```python
def snowflake_to_timestamp(tweet_id):
    """Convert Twitter Snowflake ID to Unix timestamp (ms)."""
    return (tweet_id >> 22) + 1288834974657
```

### 2.3 Username Rename Detection

- Wayback CDX API for archived profiles:
```bash
curl "http://web.archive.org/cdx/search/cdx?url=twitter.com/USERNAME*&output=json&fl=timestamp,original,statuscode"
```
- Archived pages contain JSON-LD with user ID, creation date, follower/following counts
- t.co links in archived tweets reveal previous usernames
- Same tweet ID accessible under different usernames = confirmed rename

### 2.4 Alternative Data Sources

| Source | URL Pattern | Auth Required |
|--------|-------------|---------------|
| Nitter | `nitter.poast.org/USERNAME` | No |
| Syndication API | `syndication.twitter.com/srv/timeline-profile/screen-name/USERNAME` | No |
| memory.lol | `memory.lol` | No |
| twitter.lolarchiver.com | Tracks username history | No |

**Note:** Twitter strips EXIF on upload — don't waste time on stego for Twitter-served images.

---

## 3. Tumblr Investigation

### 3.1 Blog Existence Check

```bash
# Look for x-tumblr-user header (confirms blog exists even if API returns 401)
curl -sI "https://USERNAME.tumblr.com" | grep -i "x-tumblr-user"
```

### 3.2 Post Content Extraction

Tumblr embeds post data as JSON in page HTML:
- Search for `"content":[` to find post body data
- Posts contain `type: "text"` with `text` field, and `type: "image"` with media URLs

### 3.3 Avatar Extraction

```bash
# Direct avatar endpoint (redirects to CDN URL)
curl -sL "https://USERNAME.tumblr.com/avatar/512" -o avatar.jpg

# API endpoint
curl -sL "https://api.tumblr.com/v2/blog/USERNAME.tumblr.com/avatar/512" -o avatar.jpg
```

Available sizes: 16, 24, 30, 40, 48, 64, 96, 128, 512. Always download highest resolution.

**Key insight:** Tumblr preserves more metadata in avatars than in post images. Visual steganography (tiny/low-contrast text) may be hidden in avatar images — always view at full resolution and check all corners/edges.

---

## 4. BlueSky Public API

No authentication required. All endpoints use `public.api.bsky.app`.

```bash
# Search posts
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=QUERY&sort=latest" | jq '.posts[].record.text'

# Search accounts
curl -s "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?q=USERNAME" | jq '.actors[].handle'

# Get profile
curl -s "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=USER.bsky.social" | jq

# Get author feed (all posts)
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=USER.bsky.social&limit=50" | jq '.feed[].post.record.text'

# Get post thread (including replies)
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=at://did:plc:.../app.bsky.feed.post/..." | jq
```

**Search filters:**
```
from:username        # Posts from specific user
since:2025-01-01     # Date range
has:images           # Posts with images
```

---

## 5. Discord API Enumeration

Flags/data may be hidden in Discord server metadata not visible in normal UI.

**Hiding spots:** Role names, animated GIF emoji (data in brief frames), message embeds, server description, stickers, events.

```bash
TOKEN="your_user_token"

# List roles
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/roles"

# List emojis
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/emojis"

# Search messages
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/messages/search?content=keyword"
```

**Animated emoji technique:** Download GIF, extract frames — hidden data in brief frames invisible at normal speed:
```bash
# Extract all frames from animated GIF
convert emoji.gif frame_%03d.png
# Inspect each frame for hidden text/data
```

---

## 6. Strava Fitness Route OSINT

Fitness apps are high-value OSINT targets — users rarely restrict activity visibility.

### 6.1 Public Data Exposure

- Public athlete profiles: `https://www.strava.com/athletes/<id>`
- Activity maps show GPS routes with start/end points
- Privacy zones can be circumvented by analyzing route shapes outside the zone
- Segment leaderboards reveal athlete locations without following them

### 6.2 Location Extraction Workflow

1. Find target's Strava profile via username enumeration (whatsmyname, Osint Industries)
2. Check public activities for GPS route maps
3. Identify route start/end points or frequent locations
4. Search endpoint location on Google Maps
5. Verify with Google Maps user-submitted photos

**Key insight:** A single public run reveals home/work neighborhoods. Cross-reference GPS endpoints with Google Maps to identify specific parks, buildings, or landmarks.

**Detection triggers:** Challenge mentions exercise, running, cycling, fitness, GPS, health tracking. Target persona has active/athletic profile.

---

## 7. Platform False Positives

Platforms that return HTTP 200 but no real profile:

| Platform | Behavior | How to Distinguish |
|----------|----------|-------------------|
| Telegram (`t.me/USER`) | Always returns 200 | Check title: "View" = exists, "Contact" = doesn't |
| TikTok | Returns 200 | Check body for "Couldn't find this account" |
| Smule | Returns 200 | Check body for "Not Found" |
| linkin.bio | Returns 200 | Redirects to Later.com product page for unclaimed names |
| Instagram | Returns 200 | Shows login wall — may or may not exist |

---

## 8. Username Metadata Mining

Usernames often embed geographic or temporal signals:

| Pattern | Example | Signal |
|---------|---------|--------|
| Trailing digits = postal/ZIP code | `LinXiayu35170` | 35170 = Bruz, France |
| Birth year suffix | `jsmith1998` | Born 1998 |
| Area code prefix | `user212nyc` | 212 = Manhattan |
| Country code | `player44uk` | +44 = United Kingdom |

Cross-reference extracted codes with postal code databases, phone number registries, or geographic gazetteers.

### Priority Platforms for Username Enumeration

**Standard:** Twitter/X, Tumblr, GitHub, Reddit, Bluesky, Mastodon
**Media:** Spotify, SoundCloud, Steam, Keybase
**Fitness/GPS:** Strava, Garmin Connect, MapMyRun (leak physical locations)
**Other:** Pastebin, LinkedIn, YouTube, TikTok
**Bio-link services:** linktr.ee, bio.link, about.me

---

## 9. Share Link Identity Extraction (ShareTrace)

**Tool:** [sharetrace](https://github.com/7onez/sharetrace) (Python)

Extracts identity information embedded in social media and platform share links. When users share content via platform-generated links, those links often contain metadata about the sharer — usernames, user IDs, avatars, and account details.

**Installation:**
```bash
git clone https://github.com/7onez/sharetrace.git
cd sharetrace
pip3 install -r requirements.txt
```

**Usage:**
```bash
# Analyze a share link (plain text output)
python -m sharetrace "https://vm.tiktok.com/ABC123"

# JSON output for piping/scripting
python -m sharetrace "https://vm.tiktok.com/ABC123" --json

# List all supported platforms
python -m sharetrace --list

# Suppress banner
python -m sharetrace "https://..." --quiet
```

### 9.1 Supported Platforms (11)

| Platform | Extracts | Link Format Notes |
|----------|----------|-------------------|
| **TikTok** | User ID, username, nickname, country, avatar, signature, device, share method, timestamp, follower/following/video/heart counts, private status, DM availability | Short links only: `vm.tiktok.com`, `vt.tiktok.com`, `tiktok.com/t` |
| **Instagram** | Username, user ID, display name, profile URL, profile pic | Data expires ~24h; fresh links only |
| **Discord** | User ID, username, display name, avatar, account creation time | Vanity invites may lack inviter data |
| **ChatGPT** | Display name | — |
| **Claude** | Display name, user ID | — |
| **Perplexity** | Username, avatar, user ID | — |
| **Microsoft** | Email | SharePoint/OneDrive personal links; no HTTP request needed |
| **Pinterest** | Username, user ID, display name, avatar, profile URL | Short links only: `pin.it` with invite code |
| **Substack** | User ID, name, handle, bio, avatar, profile setup date | Requires referral link (`?r=` parameter) |
| **Suno** | Username, display name, avatar, profile URL | — |
| **Telegram** | User ID | Decoded from `joinchat` hash; no HTTP needed. `AAAAA`-prefix = empty |

### 9.2 OSINT Value

- **Deanonymization via share links:** A target shares a TikTok video link in a forum — sharetrace reveals their TikTok username, country, follower count, and device type without visiting TikTok
- **Microsoft email extraction:** OneDrive/SharePoint personal share links embed the sharer's email address — extracted locally, no HTTP request needed
- **Discord invite attribution:** Server invite links can reveal who created the invite — user ID, username, display name, avatar, and account creation timestamp
- **Telegram user ID from join links:** `joinchat` hashes decode to numeric user IDs without contacting Telegram servers
- **AI platform identity:** ChatGPT and Claude share links reveal the sharer's display name and user ID

### 9.3 Integration with Case Model

- Extracted usernames → register as USERNAME subjects → feed to `/username` enumeration
- Extracted emails (Microsoft) → register as EMAIL subjects → feed to `/email-deep`
- Extracted user IDs → register as persistent identifiers on existing subjects
- Profile URLs → register as findings with trust score 4 (platform-verified)
- Account creation times (Discord) → feed to `/timeline`
- Country/device data (TikTok) → register as Location/Hardware subjects

### 9.4 Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| User ID from share link | HIGH | Platform-generated identifier |
| Username from share link | HIGH | Direct platform data |
| Email from Microsoft link | HIGH | Locally decoded, no HTTP |
| Telegram user ID from hash | HIGH | Mathematical decoding |
| Display name | MEDIUM | User-controlled, changeable |
| Avatar URL | MEDIUM | May be updated or removed |
| Instagram data from expired link | LOW | Data expires ~24h |

### 9.5 Limitations

- **Time-sensitive:** Instagram profiles expire ~24h after sharing
- **Link format constraints:** TikTok requires short links; Pinterest requires invite codes
- **No auth bypass:** Cannot extract data from private/gated content
- **Browser impersonation:** Uses `curl-cffi` to mimic Chrome; may be detected by aggressive bot protection

---

## 10. Multi-Platform OSINT Chains

### Pattern: Platform Chaining

Each platform links to the next — follow the breadcrumbs:
1. Start with known username → enumerate across ALL platforms
2. Find profile on platform X with clues pointing to platform Y
3. Discovered new username → enumerate again
4. Repeat until you find the target data

### Example Chain

Reddit username → Spotify social link → Base58-encoded string → Spotify playlist descriptions (base64) → first-letter acrostic from song titles.

### Platform-Specific Data Locations

| Platform | Where to Look |
|----------|--------------|
| Spotify | Playlist names, artist bio, song title initials |
| BlueSky | Post content, replies to official posts |
| Tumblr | Avatar image, post text |
| Reddit | Post/comment content |
| SoundCloud | Track description |
| GitHub | Issue comments, PR reviews, commit messages, wiki |

---

## 11. Confidence Ratings

| Finding | Confidence | Notes |
|---------|-----------|-------|
| Twitter numeric User ID match | HIGH | Persistent identifier |
| Snowflake timestamp decode | HIGH | Mathematical certainty |
| BlueSky API profile data | HIGH | Direct from platform |
| Username across platforms (photo match) | HIGH | Visual confirmation |
| Username across platforms (name only) | MEDIUM | May be different person |
| Strava GPS endpoint location | HIGH | Hardware GPS data |
| Platform false positive filtered | MEDIUM | Requires manual verification |

---

## 12. Reddit Investigation

### 12.1 User Analysis Tools

| Tool | URL | Auth | Notes |
|------|-----|------|-------|
| Reddit User Analyser | https://reddit-user-analyser.netlify.app/ | No | Activity patterns, subreddit frequency, posting history, karma breakdown |
| RedditMetis | https://redditmetis.com/ | No | Word clouds, activity heat maps, top subreddits, sentiment |
| Reddit Comment Search | https://www.redditcommentsearch.com/ | No | Search all comments by a specific username |

### 12.2 Investigation Workflow

1. Enter target username into Reddit User Analyser → get activity overview, post/comment ratio, most active subreddits, average posting times
2. Run RedditMetis → word cloud reveals interests/topics; heat map reveals timezone (posting schedule correlates with waking hours)
3. Search specific keywords in their comments via Reddit Comment Search
4. Check for personal info leaks: location mentions, employer references, real name in old posts
5. Cross-reference active subreddits with geographic/professional signals (e.g., r/denver + r/nursing = Denver nurse)

### 12.3 Google Dork Patterns

```
site:reddit.com/user/USERNAME
site:reddit.com "USERNAME" "I live in" OR "I work at" OR "my name is"
site:reddit.com/r/SUBREDDIT "USERNAME"
```

### 12.4 Key Signals

- **Posting schedule** → timezone/location inference
- **Subreddit activity** → interests, profession, location, political views
- **Flair text** → self-identified location, credentials, affiliations
- **Award-giving history** → links to payment method (premium features)
- **Cake day** → account creation date

---

## 13. Instagram Investigation

### 13.1 Tool Inventory

| Tool | URL/Install | Auth | Notes |
|------|------------|------|-------|
| **Osintgram** | `git clone https://github.com/Datalux/Osintgram` | No (public profiles) | Interactive shell — followers, following, geo-tagged posts, comments, stories |
| **instaloader** | `pip3 install instaloader` | No (public profiles) | Download posts, stories, highlights, metadata, profile pic. CLI tool |
| **toutatis** | `pip3 install toutatis` | No | Extract email/phone from Instagram accounts via Instagram API |
| **InstaHunt** | https://instahunt.co/ | No | Geo-search: find Instagram posts near a location |

### 13.2 Investigation Workflow

```
Step 1: Profile enumeration
  └─ instaloader <username> --no-pictures --metadata-json
  └─ Gets: bio, follower/following count, post count, external URL, business category

Step 2: Contact info extraction (toutatis)
  └─ toutatis -u <username> -s <session_id>
  └─ May reveal: email, phone number (if account has contact info enabled)

Step 3: Geo-tagged post analysis (InstaHunt / Osintgram)
  └─ InstaHunt: search by location → find posts near target area
  └─ Osintgram: photos_location → extract GPS from all geo-tagged posts

Step 4: Social graph analysis (Osintgram)
  └─ followers / following → identify close connections
  └─ comments → who interacts most? (relationship mapping)

Step 5: Media download + EXIF check
  └─ instaloader <username> → downloads all public media
  └─ Note: Instagram strips EXIF from uploads. Geo comes from in-app tagging only.
```

### 13.3 CLI Commands

```bash
# Download all public posts with metadata
instaloader <username> --no-video-thumbnails --geotags

# Download just profile info (no media)
instaloader --no-pictures --no-videos --no-video-thumbnails <username>

# Osintgram interactive shell
cd Osintgram && python3 main.py <username>
# Commands: followers, following, fwersemail, fwingsemail, photos_location, comments
```

### 13.4 Key Signals

- **Tagged locations** → frequented places (home, work, gym, restaurants)
- **Bio links** → personal website, Linktree, other social profiles
- **Follower/following overlap** → mutual connections reveal inner circle
- **Story highlights** → curated self-presentation, often reveals interests
- **Business accounts** → expose category, contact email/phone, address
- **Note:** Instagram strips EXIF metadata on upload — geo-tags come from in-app location tagging only

---

## 14. TikTok Investigation

### 14.1 Tool Inventory

| Tool | URL/Install | Auth | Notes |
|------|------------|------|-------|
| **TikTok Timestamp** | https://bellingcat.github.io/tiktok-timestamp/ | No | Extract exact upload timestamp from any TikTok video URL (Bellingcat tool) |
| **TikTok Scraper** | `npm i -g tiktok-scraper` | No | Scrape user data, hashtags, trending, music. CLI tool |
| **Tokcount** | https://tokcount.com/ | No | TikTok analytics — follower counts, engagement metrics |

### 14.2 Investigation Workflow

```
Step 1: Extract video timestamps (TikTok Timestamp)
  └─ Paste video URL → get exact upload date/time in UTC
  └─ Useful for establishing timeline of events

Step 2: Profile analysis (Tokcount)
  └─ Follower/following counts, engagement rate, posting frequency

Step 3: Scrape user content (tiktok-scraper)
  └─ tiktok-scraper user <username> --download
  └─ Gets: video URLs, descriptions, hashtags, music, stats

Step 4: Share link analysis (ShareTrace — Section 9)
  └─ TikTok short links (vm.tiktok.com) reveal: user ID, username, 
     nickname, country, device, follower counts, DM status
```

### 14.3 Key Signals

- **Video backgrounds** → location clues (room details, outdoor landmarks, signage)
- **Audio/music** → regional music trends indicate geography
- **Hashtags** → interest mapping, community membership
- **Duets/Stitches** → relationship mapping with other creators
- **Comment language** → audience/creator language and location
- **Device info via share links** → iPhone vs Android, country code

---

## 15. Telegram Investigation (Extended)

### 15.1 Search Tools

| Tool | URL | Auth | Notes |
|------|-----|------|-------|
| **TGStat** | https://tgstat.com/search | No | Full Telegram post/channel/group search with analytics, growth tracking |
| **TelegramDB** | https://telegramdb.org/ | No | Search channels, groups, and members by keyword |
| **Telegago** (Google CSE) | https://cse.google.com/cse?&cx=006368593537057042503:efxu7xprihg | No | Custom Google search engine indexed for Telegram content |
| **Lyzem** | https://lyzem.com/ | No | Telegram post search engine |

### 15.2 Investigation Workflow

```
Step 1: Search for target across Telegram (TGStat + TelegramDB)
  └─ Search by username, keyword, or phone number
  └─ Find channels they admin, groups they appear in

Step 2: Analyze channel/group content (TGStat)
  └─ Subscriber growth → detect bot inflation
  └─ Post frequency and engagement → activity patterns
  └─ Top posts → key content and interests

Step 3: Google indexed Telegram content (Telegago CSE)
  └─ Catches content TGStat may miss
  └─ Useful for finding specific mentions of a target

Step 4: Username/phone correlation
  └─ Telegram usernames often reused on other platforms → feed to /username
  └─ Phone number visible to contacts → if known, resolve it with telegram_lookup (§15.4)

Step 5: Join link analysis (ShareTrace — Section 9)
  └─ joinchat hashes decode to numeric user IDs without contacting Telegram
```

### 15.3 Key Signals

- **Channel admin** → ownership/affiliation
- **Username** → often reused across platforms (high correlation value)
- **Phone number** → visible to contacts; some bots expose it
- **Message forwarding headers** → reveal original author of forwarded messages
- **Subscriber demographics** → TGStat shows audience location/language distribution
- **Bot interactions** → usage patterns reveal interests and services used

### 15.4 Phone → Telegram Account Resolution (`telegram_lookup`)

Telegram exposes no public phone lookup. The one reliable method is the client's own contact
import: a logged-in user account imports the number as a contact, and Telegram returns the user it
belongs to — unless the owner set *Privacy → Phone Number → Who can find me by my number* to
*My Contacts*. `intel_engine/WebPivot/tools/wp_telegram.py` (MCP `telegram_lookup`) automates that
against the analyst's **research account**, never a personal one.

```
Setup (once):
  pip install telethon [python-socks]            # optional dependency, analyst's own env
  TELEGRAM_API_ID / TELEGRAM_API_HASH            # my.telegram.org → API development tools, in .env
    — or — pip install opentele2 [qrcode pillow] # official-app api_id + realistic device; no own API id
  python3 wp_telegram.py login                   # interactive; YOU type phone, code, 2FA
  python3 wp_telegram.py login --qr [--profile desktop|android|ios]   # scan with the research phone
  python3 wp_telegram.py login --tdata DIR --own-account [--passcode-prompt]  # own Desktop install
  python3 wp_telegram.py status --sessions       # backend/device, active sessions, consistency checks

Phone (OUTBOUND, confirm two-step):
  python3 wp_telegram.py phone +447700900000             # BRIEFING only — nothing sent
  python3 wp_telegram.py phone +447700900000 --confirm-import  # import → read → DeleteContacts (finally)

Public entity (no import, no confirm):
  python3 wp_telegram.py resolve @example_channel --confirm   # without --confirm: briefing only
  python3 wp_telegram.py resolve https://t.me/+AbCdEfGhIjKl --confirm   # invite PREVIEW; never joins
```

What a hit returns: numeric user id (persistent across username changes — the identifier to
record), every username including collectible (Fragment) ones, first/last name, bot / verified /
premium / scam / fake flags, a last-seen bucket (exact time only if the owner's privacy allows),
and the profile photo as sha256 + dimensions (bytes only with `--save-photo DIR`, outside the repo
or in the case folder) — feed the photo to reverse image search, the username to `/username`.

Operational rules:

- **Footprint.** The owner is not notified, but the import is logged against the research account,
  and if the owner ever saves the research account's number they see each other as contacts. The
  tool deletes every contact it imported; contacts that pre-existed are left alone.
- **Rate limits.** Imports are throttled per account and day. A `FloodWait` stops the run and
  returns the partial result — do not retry in a loop; a research account that keeps hitting it
  gets limited or banned. Small batches (`max_phones_per_run` in `references/telegram.json`).
- **Session = credential.** The session file (default `~/.config/cti-expert/sessions/`, override
  `$TELEGRAM_SESSION`) logs in as the research account. It is created only by the tool's own
  interactive login; no code, password, cookie or session string is ever passed as an argument.
- **A miss is not absence.** "Not found" covers both "not on Telegram" and "findable by contacts only".
- **One device per session, for life.** With opentele2 the session presents an official Telegram
  app's api_id and a generated device (`--profile`, default desktop). Both are fixed at login and
  stored in the session sidecar; every later run reuses them, and a different `--profile` against
  the same session is refused — an authorisation whose api_id/device changes mid-life is what gets
  research accounts flagged. Want another profile? Use a new `$TELEGRAM_SESSION` path.
- **QR login.** The `tg://login?token=…` URL (printed, rendered as a terminal QR, and as a PNG in a
  private temp dir that is deleted afterwards) is a live login token while it is valid — scan it
  only with the research account's phone. It is re-created on expiry a bounded number of times
  (`qr_max_recreate`); a 2FA password is asked for in the terminal, never as an argument.
- **tdata = the analyst's OWN install only.** `--tdata` requires `--own-account` and refuses any
  directory in the repo, the case store or a `cases/` path, or next to stealer-log artefacts
  (`stealer_log_markers` in `references/telegram.json`). Using a tdata from a case or a stealer log
  is taking over a third party's account, not OSINT. The default creates a NEW authorisation; the
  desktop app keeps its own. `--reuse-desktop-session` shares the app's auth key instead (both
  clients then live or die together) and prints a warning.
- **`status --sessions` is read-only.** It lists the research account's active sessions and runs
  opentele2's consistency checks; the tool never terminates a session.

**Attribution (SKILL.md RULE 5).** A phone→account match proves the number is registered to that
Telegram account at query time — not who the person is, and not that they still control the number
(numbers are recycled). Display names, bios, usernames and photos are self-set. Every row is
`rung: "lead"` with a caveat; it never becomes a KB edge or an operator link without independent
corroboration.

---

*Social Media Platforms Module v1.0.0 — Updated with Reddit, Instagram, TikTok, Telegram*
*Part of Free OSINT Expert Skill - Phase 5*
