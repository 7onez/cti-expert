# Agent-Browser — Interactive Browser Collection & Evidence Capture

[`vercel-labs/agent-browser`](https://github.com/vercel-labs/agent-browser) is a fast
native-Rust browser-automation CLI built for AI agents. It is the skill's **primary
interactive collector** — the concrete tool behind the "agent-browser first" rule in
the Tool Priority cascade. It drives real Chrome via the DevTools Protocol and returns
**accessibility-tree snapshots** with compact `@eN` element refs (token-efficient for an
agent to read and act on), plus screenshots for evidence.

- **No API key** for core automation (only the optional `chat` natural-language mode needs
  a Vercel AI Gateway key). Apache-2.0, cross-platform (Win/macOS/Linux), MCP-capable.
- It ships its **own** agent skill + MCP server, so it works in **Claude Code and Codex** alike.

> **OPSEC:** this opens target sites in a real Chrome. For scam/malware/darknet targets run
> it on a clean VPS/sandbox (see "Where to run it"), and use a proxy/VPN where appropriate.

---

## 1. Install (auto-install on first interactive need)

Pick whichever package manager exists (no API key required):

| OS | Install the CLI | Then download Chrome |
|----|-----------------|----------------------|
| Windows | `npm install -g agent-browser` (Node 24+) · or `cargo install agent-browser` · or `scoop install agent-browser` | `agent-browser install` |
| macOS | `brew install agent-browser` · or `npm i -g agent-browser` · or `cargo install agent-browser` | `agent-browser install` |
| Linux | `npm i -g agent-browser` · or `cargo install agent-browser` | `agent-browser install` |

`agent-browser install` fetches Chrome for Testing (first run only). The bundled
installers add this under `--headless`/`-Headless` (alongside Scrapling's browser).

---

## 2. Canonical command reference (load it, don't memorize it)

agent-browser serves its own **version-matched** guide — always prefer it over any
copy here:

```bash
agent-browser skills get core          # core workflow + exact command syntax
agent-browser skills get core --full   # extended reference
agent-browser skills list              # all skill packs
```

### Core workflow: open → snapshot → act → capture
```bash
agent-browser open https://example.com      # navigate
agent-browser snapshot                       # accessibility tree with @eN element refs
agent-browser read                           # extract page text/content
agent-browser click @e12                     # act on a referenced element
agent-browser fill @e5 "query text"          # fill an input (then click/submit)
agent-browser screenshot evidence.png        # capture visual evidence
agent-browser eval "document.title"          # run JS in page context
agent-browser mcp                            # expose as an MCP server (stdio JSON-RPC)
```
Snapshot first to get `@eN` refs, then click/fill by ref. Save screenshots to a file and
attach them to the report as evidence.

---

## 3. agent-browser vs Scrapling — complementary, not conflicting

They live in **different ecosystems** (agent-browser = Rust binary via npm/brew/cargo;
Scrapling = Python via pip) and each manages **its own** browser, so there is **no
dependency or runtime conflict** — only a little extra disk if both download a browser.
Use them at different layers:

| Need | Use |
|------|-----|
| Interactive multi-step flows, logins, clicking, **screenshot evidence**, reading JS-rendered/SPA pages as an agent | **agent-browser** (primary) |
| Fast static fetch + HTML parsing (~2ms), bulk collection **inside Python scripts** | Scrapling `Fetcher` |
| Anti-bot / Cloudflare-protected pages | Scrapling `StealthyFetcher` |
| Headless JS render without agent interaction | Scrapling `DynamicFetcher` |
| Nothing above available | web search → web fetch → curl |

Rule of thumb: **agent-browser to *interact with and witness* a page; Scrapling to
*fetch and parse* pages programmatically.**

---

## 4. Where it's used (commands that benefit)

| Command / technique | How agent-browser helps |
|---------------------|--------------------------|
| `/case`, `/sweep` | Open + screenshot target sites; interactive recon; evidence for the report |
| `/scam-check` | Render a suspicious site, screenshot it, read content/redirects without trusting static HTML |
| `/visitors`, `/traffic`, `/techstack` | Read JS-heavy / login-walled analytics dashboards (SimilarWeb, etc.) |
| `social-media-platforms` | View profiles/posts that require JS or scroll; capture screenshots |
| `image-forensics-and-face-search` | Drive reverse-image / face-search upload flows (TinEye, FaceCheck, FotoForensics) and read results |
| `/gdoc`, `/sharelink` | Open share links, follow redirects, screenshot the landing/identity surface |
| `/stealer-log` follow-up | **Open the extracted admin/panel endpoints** (`admin.`, `kef.`, `ador.`…) to screenshot and confirm live actor infrastructure |
| `/report` | Embed captured screenshots as evidence exhibits |

Tag findings collected this way with `[browser]` (per the collection-method tags).

---

## 5. MCP mode (optional)

`agent-browser mcp` runs an MCP server (stdio JSON-RPC). In Claude Code or Codex you can
register it as an MCP server to expose browser actions as native tools, instead of (or in
addition to) shelling out to the CLI.
