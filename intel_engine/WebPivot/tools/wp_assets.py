"""wp_assets — the ASSET layer: same-origin JS bundles, source maps, well-known /
policy files, and the backend API endpoints baked into a build.

WHY THIS MODULE EXISTS
----------------------
The shell HTML of a modern SPA kit is nearly empty. The operator's real
configuration — backend API base, the brand/tenant name baked in at build time,
the Sentry DSN, chat-widget ids — lives in `/assets/index-<hash>.js` or a
`config.js`, and the *developer's own machine paths* survive in the `.js.map`
sourcemap. Extracting only from the HTML document misses all of it, so every
tracker/SaaS/crypto regex the harness already owns was being pointed at the wrong
text on exactly the kits that matter most.

WHAT IT COLLECTS
----------------
1. **JS bundles** — same-registrable-domain `<script src>` files, priority-ordered
   (config/env names first, then hashed build artifacts), capped by count + bytes.
   Known third-party libraries are skipped. Each bundle's sha256 is a re-skin
   resistant kit fingerprint: a rebrand changes the favicon and the DOM, not the
   compiled bundle.
2. **Source maps** — `sourceMappingURL` → `.js.map`, whose `sources[]` carries
   absolute developer paths (`/Users/<dev>/…`, `webpack://<project>/…`). Developer
   username + internal project name are among the strongest passive attribution
   artifacts that exist, and they survive every front-end re-skin.
3. **Well-known / policy files** — `robots.txt`, `sitemap.xml`, `ads.txt`,
   `app-ads.txt`, `security.txt`, `humans.txt`, `apple-app-site-association`.
   `ads.txt` in particular yields the AdSense `pub-` publisher id, an owner-tied
   token as strong as a GA4 property.
4. **API endpoints** — `baseURL`/`apiUrl`/`VUE_APP_*`/`REACT_APP_*`/`NEXT_PUBLIC_*`
   assignments, `wss://` sockets, and `/graphql` endpoints found in the bundles.
   In a white-label kit the backend host is the single strongest same-operator
   link: every front rotates, the backend does not.

OPSEC / FOOTPRINT
-----------------
Fetching the page's own JS is *less* anomalous than not fetching it — a real
browser retrieves every one of these files. The well-known probes are the extra
footprint (a handful of tiny GETs on standard, crawler-expected paths). All of it
is gated to a LIVE, non-archived origin and suppressed on crawled sub-pages, and
`--no-assets` / `--no-well-known` turn each half off. Nothing here brute-forces
paths: only files the page itself references, plus a fixed list of published
standards. Directory brute-forcing is a different (loud, active) capability and
deliberately does not live here.
"""
from wp_common import *  # noqa
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
from wp_net import fetch  # noqa
from wp_extract import (extract_trackers, extract_saas, extract_crypto,  # noqa
                        extract_socials, extract_telegram, EMAIL_RE,
                        BOILERPLATE_EMAIL_HOSTS)

# ------------------------------------------------------------------ toggles (set by main())
COLLECT_ASSETS = True        # --no-assets turns off JS bundle + sourcemap collection
COLLECT_WELL_KNOWN = True    # --no-well-known turns off the policy-file probes
MAX_JS_FILES = 6             # --assets-max
MAX_JS_BYTES = 2_000_000     # total budget across all bundles
MAX_MAPS = 3                 # sourcemaps are large; only the top few bundles


# --- third-party libraries: fetching them tells us about the library, not the operator.
_LIB_SKIP_RE = re.compile(
    r"(?:^|/)(?:jquery|zepto|bootstrap|popper|swiper|slick|owl\.?carousel|lodash|underscore|"
    r"moment|dayjs|react|react-dom|vue\.(?:runtime|min|global)|angular|ember|backbone|gsap|"
    r"aos|wow|modernizr|tailwind|fontawesome|all\.min|polyfill|core-js|regenerator|html5shiv|"
    r"respond|select2|datatables|three|tinymce|ckeditor|clipboard|sweetalert|toastr|izitoast|"
    r"magnific|fancybox|lightbox|isotope|masonry|typed|particles|smoothscroll|wow\.min|"
    r"owl|flickity|splide|lazysizes|hammer|velocity|anime|scrollreveal)[.\-]", re.I)

# --- name hints that a file carries build/runtime CONFIG rather than view code.
_CONFIG_HINT_RE = re.compile(
    r"(?:config|conf|env|environment|setting|constant|endpoint|runtime|api|server|global)", re.I)

# --- a content-hashed build artifact (Vite `index-B3GD2NjP.js`, webpack `app.7f3c9a2b.chunk.js`)
_HASHED_BUILD_RE = re.compile(r"[-.][A-Za-z0-9_]{6,12}\.(?:chunk\.)?(?:js|mjs)$")

_ENTRY_HINT_RE = re.compile(r"(?:^|/)(?:main|index|app|bundle|entry)[-.]?", re.I)

_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"*]+)")

_WEBPACK_PATH_RE = re.compile(r"webpack://([^\"'\s\\)]{1,200})")

# Developer home directories that leak into sourcemap `sources[]` / webpack paths.
# JSON-escaped Windows separators (\\Users\\) are handled by the {1,2} repeats.
_DEV_HOME_RE = re.compile(
    r"(?:/Users/([A-Za-z0-9._-]{2,32})/"
    r"|/home/([A-Za-z0-9._-]{2,32})/"
    r"|[Cc]:\\{1,2}Users\\{1,2}([A-Za-z0-9._ -]{2,32})\\{1,2})")

# Build-time environment variables inlined by the bundler. `VUE_APP_BRAND:"<tenant>"` is the
# canonical white-label tell: one platform, many fronts, the tenant name compiled in.
_BUILD_ENV_RE = re.compile(
    r"""["']?((?:VUE_APP|REACT_APP|NEXT_PUBLIC|NUXT_ENV|VITE|GATSBY|EXPO_PUBLIC|"""
    r"""SVELTE|PUBLIC|APP)_[A-Z0-9_]{2,40})["']?\s*[:=]\s*["']([^"'\n\r]{1,200})["']""")

# Explicit API-base assignments (axios.create({baseURL}), config objects, constants).
_API_ASSIGN_RE = re.compile(
    r"""(?:baseURL|baseUrl|base_url|apiUrl|apiURL|api_url|apiBase|apiBaseUrl|apiHost|"""
    r"""API_BASE|API_URL|API_HOST|API_ROOT|SERVER_URL|serverUrl|serviceUrl|gatewayUrl|"""
    r"""BASE_API|baseApi|requestUrl|host)["']?\s*[:=]\s*["']((?:https?:)?//[^"'\s]{4,300})["']""")

_WS_RE = re.compile(r"""["']((?:wss?:)?//[^"'\s]{4,300})["']""")

_GRAPHQL_RE = re.compile(r"""["'](https?://[^"'\s]{0,200}/graphql[^"'\s]{0,80})["']""")

# Any quoted absolute/protocol-relative URL in the bundle — the "hrefs" that extract_socials
# and extract_telegram expect (a bundle has no <a> tags to harvest).
_QUOTED_URL_RE = re.compile(r"""["']((?:https?:)?//[^"'\s)]{4,300})["']""")

_ABS_URL_RE = re.compile(
    r"""["'](https?://((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})"""
    r"""(?::\d{2,5})?(?:/[^"'\s]{0,200})?)["']""", re.I)

# Hostname labels that mark a backend/API tier rather than a marketing front.
_API_HOST_HINT_RE = re.compile(
    r"^(?:api|apis|api\d|backend|back|be|gateway|gw|service|services|svc|server|srv|"
    r"admin|manage|manager|core|data|rpc|ws|socket|push|auth|sso|account|pay|payment|"
    r"trade|quote|market|market-?data|upload|file|oss|im|chat)\b", re.I)

# Infrastructure we never treat as the operator's backend (analytics/CDN/SaaS endpoints
# every site talks to). Kept separate from the HTML-side CDN list because bundles reference
# far more third-party endpoints than the document does.
# DATA: references/third_party_noise.json -> backend_noise_suffixes (add providers there).
_BACKEND_FALLBACK = {"backend_noise_suffixes": [
    "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "facebook.net", "cloudflare.com", "jsdelivr.net", "unpkg.com",
    "sentry.io", "w3.org", "schema.org", "githubusercontent.com"]}
_BACKEND_NOISE_SUFFIXES = tuple(
    load_ref(ref_path(__file__, "third_party_noise.json"),
             _BACKEND_FALLBACK)["backend_noise_suffixes"])


def _skip_backend(host: str) -> bool:
    h = (host or "").lower()
    return not h or any(h == s or h.endswith("." + s) for s in _BACKEND_NOISE_SUFFIXES)


def _same_site(url: str, self_host: str) -> bool:
    """True when `url` resolves inside the seed's own registrable domain (or is relative)."""
    try:
        netloc = urlparse(url).netloc
    except Exception:
        return False
    if not netloc:
        return True                     # relative path → same origin
    h = strip_www(netloc).split(":")[0]
    return bool(self_host) and _registrable(h) == _registrable(self_host)


def _js_priority(url: str) -> int:
    """Rank a candidate bundle: config-ish names first, then hashed build artifacts, then
    entry points. Decides WHICH files get spent against the byte budget."""
    name = urlparse(url).path.rsplit("/", 1)[-1] or url
    if _CONFIG_HINT_RE.search(name):
        return 3
    if _HASHED_BUILD_RE.search(name):
        return 2
    if _ENTRY_HINT_RE.search(name):
        return 1
    return 0


def select_bundles(script_srcs, base_url: str, self_host: str, limit: int = None):
    """Resolve + filter + priority-order the page's own script URLs.

    Returns (chosen, skipped) where skipped is a list of {'url','reason'} so a run can
    report what it declined to fetch instead of silently truncating.
    """
    limit = MAX_JS_FILES if limit is None else limit
    chosen, skipped, seen = [], [], set()
    for src in script_srcs or []:
        try:
            url = unwrap_wayback(urljoin(base_url or "", src))
        except Exception:
            continue
        url = url.split("#", 1)[0]
        if url in seen:
            continue
        seen.add(url)
        if not url.startswith(("http://", "https://")):
            continue
        name = urlparse(url).path.rsplit("/", 1)[-1]
        if not _same_site(url, self_host):
            skipped.append({"url": url, "reason": "third-party host"})
            continue
        if _LIB_SKIP_RE.search(name or ""):
            skipped.append({"url": url, "reason": "known third-party library"})
            continue
        chosen.append(url)
    chosen.sort(key=lambda u: -_js_priority(u))
    if len(chosen) > limit:
        for u in chosen[limit:]:
            skipped.append({"url": u, "reason": f"over --assets-max ({limit})"})
        chosen = chosen[:limit]
    return chosen, skipped


def fetch_bundles(script_srcs, base_url: str, self_host: str, ua: str = DEFAULT_UA,
                  proxy: str = None, timeout: int = 20, limit: int = None,
                  byte_budget: int = None):
    """Fetch the selected same-origin bundles. Returns (files, skipped, texts_by_url).

    Each file is {'url','bytes','sha256','name'}. `texts_by_url` holds each bundle's
    decoded source so the sourcemap step and the extractors reuse it — every bundle is
    fetched exactly ONCE per run (re-fetching would double the footprint on the target).
    """
    byte_budget = MAX_JS_BYTES if byte_budget is None else byte_budget
    chosen, skipped = select_bundles(script_srcs, base_url, self_host, limit=limit)
    files, texts_by_url, spent = [], {}, 0
    for url in chosen:
        if spent >= byte_budget:
            skipped.append({"url": url, "reason": f"byte budget exhausted ({byte_budget})"})
            continue
        try:
            _, status, _, body = fetch(url, timeout=timeout, ua=ua, proxy=proxy)
        except Exception as e:
            skipped.append({"url": url, "reason": f"fetch failed: {e}"})
            continue
        if status >= 400 or not body:
            skipped.append({"url": url, "reason": f"HTTP {status}"})
            continue
        body = body[:max(0, byte_budget - spent)]
        spent += len(body)
        text = body.decode("utf-8", "ignore")
        texts_by_url[url] = text
        files.append({
            "url": url,
            "name": urlparse(url).path.rsplit("/", 1)[-1],
            "bytes": len(body),
            # A bundle sha256 survives the rebrands that break favicon / DOM-skeleton hashes:
            # the same compiled kit deployed under a new brand yields the identical digest.
            "sha256": hashlib.sha256(body).hexdigest(),
        })
    return files, skipped, texts_by_url


# ------------------------------------------------------------------ source maps
def sourcemap_url(js_text: str, js_url: str):
    """The `.map` URL a bundle points at, resolved against the bundle. Data-URI maps are
    returned as-is so the caller can decode them without a second request."""
    m = _SOURCEMAP_RE.search(js_text or "")
    if not m:
        return None
    ref = m.group(1).strip()
    if ref.startswith("data:"):
        return ref
    try:
        return urljoin(js_url, ref)
    except Exception:
        return None


def dev_identity(paths):
    """Split developer paths into (usernames, project_roots).

    A `/Users/<name>/…` or `webpack://<project>/…` path is the operator's own build
    machine leaking through the bundler — the highest-attribution artifact in this module.
    node_modules paths are dependency noise and never contribute a project root.
    """
    usernames, roots = [], []
    for p in paths or []:
        for m in _DEV_HOME_RE.finditer(p):
            name = next((g for g in m.groups() if g), None)
            # Generic/service accounts are CI runners, not a person.
            if name and name.lower() not in (
                    "root", "admin", "administrator", "user", "public", "default",
                    "runner", "builder", "build", "jenkins", "ubuntu", "ec2-user",
                    "node", "app", "docker", "vsts", "circleci", "travis", "gitlab-runner"):
                usernames.append(name)
        if "node_modules" in p:
            continue
        wm = _WEBPACK_PATH_RE.search(p)
        if wm:
            root = wm.group(1).split("/")[0].strip()
            if root and root not in (".", "..", "src", "webpack") and not root.startswith("./"):
                roots.append(root)
    return uniq(usernames), uniq(roots)


def parse_sourcemap(raw: str):
    """Parse a `.js.map` body → {'sources','sources_count','dev_paths','usernames',
    'project_roots','has_sources_content'}. Returns None if it isn't a source map."""
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict) or "sources" not in data:
        return None
    sources = [s for s in (data.get("sources") or []) if isinstance(s, str)]
    root = data.get("sourceRoot") or ""
    if root:
        sources = [root.rstrip("/") + "/" + s.lstrip("./") if not s.startswith(("http", "webpack"))
                   else s for s in sources]
    # Developer-machine paths: anything absolute or webpack:// that isn't a dependency.
    dev_paths = uniq([s for s in sources
                      if ("node_modules" not in s)
                      and (_DEV_HOME_RE.search(s) or s.startswith("webpack://")
                           or re.match(r"^[A-Za-z]:\\", s))])
    usernames, roots = dev_identity(sources)
    return {
        "sources_count": len(sources),
        "sources": sources[:60],
        "dev_paths": dev_paths[:40],
        "usernames": usernames,
        "project_roots": roots[:20],
        # sourcesContent means the ORIGINAL un-minified code (with the operator's comments,
        # often in their own language) is recoverable from this one file.
        "has_sources_content": bool(data.get("sourcesContent")),
    }


def fetch_source_maps(files, texts_by_url, ua: str = DEFAULT_UA, proxy: str = None,
                      timeout: int = 20, limit: int = None):
    """For each bundle that advertises a sourceMappingURL, fetch + parse the map."""
    limit = MAX_MAPS if limit is None else limit
    maps = []
    for f in files:
        if len(maps) >= limit:
            break
        text = texts_by_url.get(f["url"]) or ""
        murl = sourcemap_url(text, f["url"])
        if not murl:
            continue
        if murl.startswith("data:"):
            try:
                b64 = murl.split(",", 1)[1]
                raw = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", "ignore")
            except Exception:
                continue
            parsed = parse_sourcemap(raw)
            if parsed:
                maps.append(dict(parsed, url=f["url"] + " (inline data: map)", for_bundle=f["url"]))
            continue
        try:
            _, status, _, body = fetch(murl, timeout=timeout, ua=ua, proxy=proxy)
        except Exception:
            continue
        if status >= 400 or not body:
            continue
        parsed = parse_sourcemap(body.decode("utf-8", "ignore"))
        if parsed:
            maps.append(dict(parsed, url=murl, for_bundle=f["url"]))
    return maps


# ------------------------------------------------------------------ API / backend endpoints
def extract_api_endpoints(text: str, self_host: str = ""):
    """Harvest the backend surface a build was compiled against.

    Returns {'api_bases','same_site_api','websockets','graphql','build_env','other_hosts'}.
    `api_bases` are OFF-apex backends — in a white-label kit that host is shared by every
    front and is the strongest same-operator link available from the front end.
    """
    text = text or ""
    api_bases, same_site, other = [], [], []

    def _place(url):
        u = url
        if u.startswith("//"):
            u = "https:" + u
        try:
            host = strip_www(urlparse(u).netloc).split(":")[0]
        except Exception:
            return
        if not host or _skip_backend(host):
            return
        if self_host and _registrable(host) == _registrable(self_host):
            same_site.append(u)
        else:
            api_bases.append(u)

    for m in _API_ASSIGN_RE.finditer(text):
        _place(m.group(1))

    websockets = []
    for m in _WS_RE.finditer(text):
        u = m.group(1)
        if u.startswith("//"):
            continue                     # protocol-relative http asset, not a socket
        try:
            host = strip_www(urlparse(u).netloc).split(":")[0]
        except Exception:
            continue
        if host and not _skip_backend(host):
            websockets.append(u)

    graphql = [m.group(1) for m in _GRAPHQL_RE.finditer(text)]

    # Absolute URLs whose HOSTNAME looks like a backend tier, even without an explicit
    # baseURL assignment (hand-rolled fetch() calls, string-concatenated endpoints).
    for m in _ABS_URL_RE.finditer(text):
        url, host = m.group(1), strip_www(m.group(2)).split(":")[0]
        if _skip_backend(host):
            continue
        label = host.split(".")[0]
        if _API_HOST_HINT_RE.match(label):
            if self_host and _registrable(host) == _registrable(self_host):
                same_site.append(url)
            else:
                api_bases.append(url)
        elif not (self_host and _registrable(host) == _registrable(self_host)):
            other.append(host)

    build_env = {}
    for m in _BUILD_ENV_RE.finditer(text):
        k, v = m.group(1), m.group(2).strip()
        # Empty strings and pure booleans/ports carry no attribution value.
        if v and v.lower() not in ("true", "false", "null", "undefined") and len(v) > 1:
            build_env.setdefault(k, [])
            if v not in build_env[k]:
                build_env[k].append(v)

    return {
        "api_bases": uniq(api_bases)[:25],
        "same_site_api": uniq(same_site)[:25],
        "websockets": uniq(websockets)[:15],
        "graphql": uniq(graphql)[:10],
        "build_env": {k: v[:5] for k, v in list(build_env.items())[:40]},
        "other_hosts": uniq(other)[:40],
    }


# ------------------------------------------------------------------ SPA route tables
# A single-page app ships its ENTIRE routing table inside the bundle: Vue Router, React
# Router and Angular all compile to object literals carrying `path:"/…"`, and Next.js emits
# a sortedPages array. That is the app's full URL inventory — including the operator panel
# and the funnel steps — recoverable with ZERO extra requests to the target, because the
# bundle was already fetched. It is the passive answer to "what paths exist here": no
# brute-forcing, no 404 storm, nothing for the operator to notice.
#
# Routes are recorded as LEADS and as a clustering signature. This module NEVER fetches
# them — deciding to visit a discovered admin path is an analyst's call, not the tool's.

_ROUTE_PATH_RE = re.compile(r"""["']?path["']?\s*:\s*["']([^"'\n\r]{0,160})["']""")

_NEXT_PAGES_RE = re.compile(r"""sortedPages\s*:\s*\[([^\]]{0,20000})\]""")

_NEXT_DATA_RE = re.compile(
    r"""<script[^>]+id=["']__NEXT_DATA__["'][^>]*>(.*?)</script>""", re.I | re.S)

_ROUTE_NAME_RE = re.compile(
    r"""["']?path["']?\s*:\s*["'][^"'\n\r]{0,160}["']\s*,\s*["']?name["']?\s*:\s*["']"""
    r"""([A-Za-z0-9_\-. ]{1,60})["']""")

# SVG path data ("M0 0L10 10z", "m12,4 a8…") also lives behind a `path:` key in icon
# libraries — the single biggest false-positive source for this extractor.
_SVG_PATH_RE = re.compile(r"^[MmZzLlHhVvCcSsQqTtAa][\d\s.,\-]")

_ASSET_EXT_RE = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|json)$", re.I)

# The operator's own surface — a panel/console/CMS the public funnel never links to.
_ADMIN_ROUTE_RE = re.compile(
    r"(?:^|/)(?:admin|administrator|adm|manage[rs]?|management|dashboard|panel|backend|"
    r"backoffice|back-office|console|internal|staff|operator|cms|sysadmin|system|root|"
    r"super(?:admin|user)?|control|monitor|audit|logs?|config|settings?|maintenance|"
    r"developer|debug|test-?tool)\b", re.I)

# The money/identity surface — what the application actually does to a victim. Reading this
# list tells you the scam's mechanics without ever clicking through the funnel.
_FUNNEL_ROUTE_RE = re.compile(
    r"(?:^|/)(?:deposit|recharge|topup|top-up|withdraw(?:al)?|cashout|kyc|verify|"
    r"verification|identity|wallet|balance|fund|finance|payment|pay|checkout|order|"
    r"invest|trade|trading|position|contract|invite|referral|refer|bonus|reward|"
    r"commission|agent|team|vip|level|bank(?:card)?|card|transfer|remit)\b", re.I)


def _valid_route(p: str) -> bool:
    """Is this `path:` value a real application route rather than SVG data / an asset?"""
    if not p or len(p) > 120:
        return False
    if " " in p or "\t" in p:
        return False
    if _SVG_PATH_RE.match(p):                 # icon-library path data
        return False
    if _ASSET_EXT_RE.search(p):               # a bundled asset, not a route
        return False
    if p in ("/", "*", "**", "/*", "/**"):    # root + catch-alls carry no information
        return False
    if re.fullmatch(r"/?:[A-Za-z0-9_]+.*", p):        # a bare param segment (":id")
        return False
    if re.search(r"pathMatch|\(\.\*\)", p):           # vue-router catch-all
        return False
    if p.startswith(("http://", "https://", "//", "data:")):
        return False
    # Real routes are slug-ish: letters/digits/-/_ plus route-param punctuation.
    return bool(re.fullmatch(r"/?[A-Za-z0-9\-_~/.:{}\[\]()?=&+$@%]{1,120}", p))


def _normalize_route(p: str) -> str:
    """Angular declares routes without a leading slash; normalize so the two frameworks
    produce the same signature for the same app."""
    p = p.strip()
    if not p.startswith("/"):
        p = "/" + p
    return re.sub(r"/{2,}", "/", p).rstrip("/") or "/"


def extract_spa_routes(text: str, html: str = ""):
    """Recover a single-page app's routing table from its bundle (and Next.js data blob).

    Returns {'routes','count','router','admin_routes','funnel_routes','route_names',
    'signature'} — or {} when the app ships no recognizable router.

    `signature` is a sha256 over the sorted route set: two domains whose apps expose the
    IDENTICAL route inventory are running the same kit, which survives a cosmetic re-skin
    (new brand, new favicon, new colours — same compiled routing table).
    """
    text = text or ""
    routes, router = [], None

    for m in _ROUTE_PATH_RE.finditer(text):
        p = m.group(1)
        if _valid_route(p):
            routes.append(_normalize_route(p))
    if routes:
        # Best-effort framework attribution from co-occurring runtime markers.
        if re.search(r"vue-router|createRouter|createWebHistory|\$route\b", text, re.I):
            router = "vue-router"
        elif re.search(r"react-router|createBrowserRouter|RouterProvider", text, re.I):
            router = "react-router"
        elif re.search(r"@angular/router|RouterModule|ActivatedRoute", text, re.I):
            router = "angular-router"
        else:
            router = "unknown"

    # Next.js ships its route inventory as a build manifest instead of a router literal.
    for m in _NEXT_PAGES_RE.finditer(text):
        for p in re.findall(r"""["']([^"']{1,160})["']""", m.group(1)):
            if _valid_route(p):
                routes.append(_normalize_route(p))
                router = router or "next.js"
    if html:
        nd = _NEXT_DATA_RE.search(html)
        if nd:
            try:
                data = json.loads(nd.group(1))
                for key in ("page",):
                    p = data.get(key)
                    if isinstance(p, str) and _valid_route(p):
                        routes.append(_normalize_route(p))
                router = router or "next.js"
            except Exception:
                pass

    routes = uniq(routes)
    if not routes:
        return {}
    names = uniq([n for n in _ROUTE_NAME_RE.findall(text) if n.strip()])[:60]
    return {
        "router": router,
        "count": len(routes),
        "routes": routes[:300],
        "admin_routes": [r for r in routes if _ADMIN_ROUTE_RE.search(r)][:40],
        "funnel_routes": [r for r in routes if _FUNNEL_ROUTE_RE.search(r)][:40],
        "route_names": names,
        # Signature over the SORTED set so route-declaration order (which the bundler may
        # shuffle between builds) cannot change it. Needs >=3 routes to mean anything.
        "signature": (hashlib.sha256("\n".join(sorted(routes)).encode()).hexdigest()
                      if len(routes) >= 3 else None),
    }


def extract_from_bundles(text: str, self_host: str = ""):
    """Re-point the harness's existing extractors at the bundle source.

    Deliberately EXCLUDES phone extraction: minified JS is dense with numeric literals and
    PHONE_RE would return pure garbage. Crypto survives because valid_crypto_address()
    checksum-validates every candidate, and emails keep the platform-boilerplate filter.
    """
    if not text:
        return {}
    trackers = extract_trackers(text)
    if "sentry_dsn" in trackers:         # same platform-DSN filter analyze() applies to HTML
        kept = [v for v in trackers["sentry_dsn"]
                if not any(h in v.lower() for h in BOILERPLATE_EMAIL_HOSTS)]
        if kept:
            trackers["sentry_dsn"] = kept
        else:
            del trackers["sentry_dsn"]
    urls = uniq(_QUOTED_URL_RE.findall(text))
    emails = [e for e in uniq(EMAIL_RE.findall(text))
              if (el := e.lower())
              and not el.endswith((".png", ".jpg", ".gif", ".svg", ".webp", ".js", ".css"))
              and not el.split("@")[-1].endswith(BOILERPLATE_EMAIL_HOSTS)][:20]
    return {
        "trackers": trackers,
        "saas_ids": extract_saas(text),
        "crypto": extract_crypto(text),
        "socials": extract_socials(urls),
        "telegram": extract_telegram(urls),
        "emails": emails,
    }


# ------------------------------------------------------------------ well-known / policy files
# Published standards only — every path here is a documented, crawler-expected location.
# This list is FIXED on purpose: it is not a wordlist and it never grows at runtime.
WELL_KNOWN_PATHS = [
    ("robots_txt", "/robots.txt"),
    ("sitemap_xml", "/sitemap.xml"),
    ("ads_txt", "/ads.txt"),
    ("app_ads_txt", "/app-ads.txt"),
    ("security_txt", "/.well-known/security.txt"),
    ("humans_txt", "/humans.txt"),
    ("apple_app_site_association", "/.well-known/apple-app-site-association"),
]

_ADS_TXT_LINE_RE = re.compile(
    r"^\s*([a-z0-9.\-]+\.[a-z]{2,24})\s*,\s*([A-Za-z0-9\-_]{3,64})\s*,\s*"
    r"(DIRECT|RESELLER)\s*(?:,\s*([A-Za-z0-9]{4,32}))?", re.I)


def parse_ads_txt(body: str):
    """ads.txt / app-ads.txt → the publisher accounts the site declares.

    A `pub-…` id is a Google AdSense/AdManager publisher account: owner-registered,
    not copyable by a stranger, and reused across every property that operator monetizes.
    That puts it in the same strength tier as a GA4 property or a GSC verification token.
    """
    out = []
    for line in (body or "").splitlines():
        line = line.split("#", 1)[0]
        m = _ADS_TXT_LINE_RE.match(line)
        if not m:
            continue
        out.append({
            "exchange": m.group(1).lower(),
            "publisher_id": m.group(2),
            "relationship": m.group(3).upper(),
            "cert_authority_id": m.group(4) or None,
        })
        if len(out) >= 60:
            break
    return out


def parse_robots(body: str, base: str):
    disallow, sitemaps, agents = [], [], []
    for line in (body or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k == "disallow":
            disallow.append(v)
        elif k == "sitemap":
            sitemaps.append(v if v.startswith("http") else urljoin(base, v))
        elif k == "user-agent":
            agents.append(v)
    return {"disallow": uniq(disallow)[:60], "sitemaps": uniq(sitemaps)[:10],
            "user_agents": uniq(agents)[:20]}


def parse_sitemap(body: str):
    locs = uniq(re.findall(r"<loc>\s*([^<\s]{4,500})\s*</loc>", body or "", re.I))
    is_index = bool(re.search(r"<sitemapindex", body or "", re.I))
    return {"is_index": is_index, "count": len(locs), "urls": locs[:200]}


def parse_security_txt(body: str):
    contacts, others = [], {}
    for line in (body or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k == "contact":
            contacts.append(re.sub(r"^mailto:", "", v, flags=re.I))
        elif k in ("encryption", "acknowledgments", "policy", "hiring", "canonical"):
            others[k] = v
    return {"contacts": uniq(contacts)[:10], "fields": others}


def parse_aasa(body: str):
    """apple-app-site-association → Apple `<TeamID>.<bundle.id>` app identifiers.

    The iOS twin of assetlinks.json. The Team ID is an Apple Developer Program account —
    one account signs every app that operator ships, so it clusters across brands.
    """
    try:
        data = json.loads(body)
    except Exception:
        return None
    app_ids = []

    def _collect(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("appID", "appIdentifier"):
                    if isinstance(v, str):
                        app_ids.append(v)
                elif k in ("appIDs", "apps"):
                    app_ids.extend([x for x in (v or []) if isinstance(x, str)])
                else:
                    _collect(v)
        elif isinstance(node, list):
            for x in node:
                _collect(x)

    _collect(data)
    app_ids = uniq([a for a in app_ids if "." in a])
    teams = uniq([a.split(".", 1)[0] for a in app_ids if re.fullmatch(r"[A-Z0-9]{10}", a.split(".", 1)[0])])
    bundles = uniq([a.split(".", 1)[1] for a in app_ids if "." in a])
    return {"app_ids": app_ids[:20], "team_ids": teams[:10], "bundle_ids": bundles[:20]}


def fetch_well_known(origin: str, ua: str = DEFAULT_UA, proxy: str = None, timeout: int = 12):
    """GET each published policy path on `origin` (scheme://host). Returns
    {name: parsed} for the ones that exist, plus an `_attempted` roster so a run can
    report coverage instead of leaving 'nothing found' ambiguous."""
    found, attempted = {}, []
    for name, path in WELL_KNOWN_PATHS:
        url = origin.rstrip("/") + path
        attempted.append(name)
        try:
            _, status, headers, body = fetch(url, timeout=timeout, ua=ua, proxy=proxy)
        except Exception:
            continue
        if status >= 400 or not body:
            continue
        text = body.decode("utf-8", "ignore")
        ctype = (headers.get("content-type") or "").lower()
        # A SPA that 200s every path returns its index.html for these too — reject HTML
        # bodies so a catch-all route doesn't manufacture phantom policy files.
        if "text/html" in ctype or re.match(r"\s*<(?:!doctype|html)", text, re.I):
            continue
        if len(text) > 400_000:
            text = text[:400_000]
        entry = {"url": url, "bytes": len(body)}
        if name == "robots_txt":
            entry.update(parse_robots(text, origin))
        elif name == "sitemap_xml":
            entry.update(parse_sitemap(text))
            if not entry.get("count"):
                continue
        elif name in ("ads_txt", "app_ads_txt"):
            pubs = parse_ads_txt(text)
            if not pubs:
                continue
            entry["publishers"] = pubs
        elif name == "security_txt":
            entry.update(parse_security_txt(text))
            if not entry.get("contacts"):
                continue
        elif name == "humans_txt":
            entry["text"] = re.sub(r"\s+", " ", text).strip()[:1000]
            if not entry["text"]:
                continue
        elif name == "apple_app_site_association":
            parsed = parse_aasa(text)
            if not parsed or not parsed.get("app_ids"):
                continue
            entry.update(parsed)
        found[name] = entry
    found["_attempted"] = attempted
    return found


# ------------------------------------------------------------------ top-level collector
def collect(script_srcs, base_url: str, self_host: str, ua: str = DEFAULT_UA,
            proxy: str = None, timeout: int = 20, html: str = ""):
    """Run the whole asset layer for one live page. Returns the `artifacts.assets` dict.

    Safe to call unconditionally: it returns a coverage-only stub when the toggles are off,
    so the caller never has to branch and 'we did not look' stays visible in the output.
    """
    assets = {"collected": [], "skipped": [], "source_maps": [],
              "api": {}, "js_derived": {}, "routes": {}, "well_known": {},
              "coverage": {"bundles": "off", "source_maps": "off", "well_known": "off",
                           "routes": "off"}}

    combined = ""
    if COLLECT_ASSETS and base_url:
        files, skipped, texts_by_url = fetch_bundles(script_srcs, base_url, self_host,
                                                     ua=ua, proxy=proxy, timeout=timeout)
        combined = "\n".join(texts_by_url.get(f["url"], "") for f in files)
        assets["collected"] = files
        assets["skipped"] = skipped[:40]
        assets["coverage"]["bundles"] = f"{len(files)} fetched, {len(skipped)} skipped"
        if files:
            maps = fetch_source_maps(files, texts_by_url, ua=ua, proxy=proxy, timeout=timeout)
            assets["source_maps"] = maps
            assets["coverage"]["source_maps"] = f"{len(maps)} parsed"
        else:
            assets["coverage"]["source_maps"] = "no bundles to map"
        if combined:
            assets["api"] = extract_api_endpoints(combined, self_host)
            assets["js_derived"] = extract_from_bundles(combined, self_host)
        # Route table: recovered from the ALREADY-fetched bundle (+ any __NEXT_DATA__ in the
        # HTML), so it costs zero additional requests. Runs even with no bundles when the page
        # is a Next.js app, whose inventory lives in the HTML data blob.
        routes = extract_spa_routes(combined, html)
        assets["routes"] = routes
        assets["coverage"]["routes"] = (
            f"{routes['count']} routes ({routes.get('router')})" if routes else "no SPA router found")

    if COLLECT_WELL_KNOWN and base_url:
        p = urlparse(base_url)
        if p.scheme in ("http", "https") and p.netloc:
            wk = fetch_well_known(f"{p.scheme}://{p.netloc}", ua=ua, proxy=proxy,
                                  timeout=min(timeout, 12))
            attempted = wk.pop("_attempted", [])
            assets["well_known"] = wk
            assets["coverage"]["well_known"] = f"{len(wk)}/{len(attempted)} present"

    return assets


__all__ = [_n for _n in dir() if not _n.startswith("__")]
