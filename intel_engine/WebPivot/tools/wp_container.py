#!/usr/bin/env python3
"""wp_container — passive PUBLIC container-registry OSINT for a namespace or an image.

Input a namespace — a Docker Hub user/org (`example`), `ghcr.io/<owner>`, `quay.io/<ns>` — or an
image reference (`example/app:1.2`, `docker.io/library/alpine:latest`, `ghcr.io/owner/img@sha256:…`,
any OCI v2 `registry.example/ns/img:tag`) and read what the registry publishes to anyone:

  namespace  Docker Hub v2 namespaces API (repositories, description, pull/star counts,
             last_updated, registration date) + the user/org profile (full name, company,
             profile URL); Quay public repository API; GHCR has no keyless listing API, so the
             owner's public GitHub packages page is read for container package names.
  image      tags (Hub/Quay tag APIs, else /v2/<repo>/tags/list); the manifest (a multi-arch
             index/list is resolved to the reference platform, linux/amd64 by default); the
             CONFIG blob — Env, Cmd, Entrypoint, Labels (org.opencontainers.image.source /
             authors / vendor …), the `history[].created_by` build steps (which carry ENV/ARG
             values and `--build-arg` pairs) — scanned for secret shapes.
  --layers   ONLY when asked: stream each layer blob up to a byte cap (references: 50 MB per
             layer, 200 MB total; a larger layer is read partially and flagged truncated), walk
             the tar members, and secret-scan files whose PATH matches the reference patterns
             (.env, *.yml, *.properties, id_rsa, *.pem, settings.py, appsettings*.json,
             application*.yml, .npmrc, .docker/config.json …).

Registry auth is anonymous: a pull token from the registry's token endpoint (auth.docker.io,
ghcr.io/token, quay.io/v2/auth), falling back to the WWW-Authenticate Bearer challenge.

Attribution rail (SKILL.md RULE 5): every identity read from a profile, a label or a config
`author` is a LEAD (`rung: "lead"`) with a caveat — namespaces are often personal developer /
contractor / CI accounts and labels are copied from base images. Secrets are FACTS that a
credential-shaped string is public; they are never validated, and a full value is NEVER emitted
(preview = first/last 3 chars, sha256 of the value for dedupe). Nothing here writes a KB edge.

Tri-state, never raises: `registry_osint()` returns a dict, `None` when the namespace/image does
not exist, or `{"error": …}` on a transport failure before anything was collected. An HTTP 429
from any endpoint STOPS the run (partial result + `rate_limited`); there is no other local cap
besides the byte caps. All endpoints are keyless — nothing is metered, nothing is ledgered.
Endpoints, caps, member-path patterns and secret shapes are reference DATA
(`references/container_registry.json`, RULE 3).

CLI:
  python3 wp_container.py docker                         # Docker Hub namespace: repos + 3 configs
  python3 wp_container.py library/alpine:latest --json   # one image, config blob only
  python3 wp_container.py alpine --image                 # bare Hub name as an image (library/)
  python3 wp_container.py ghcr.io/example --max-images 0 # list only
  python3 wp_container.py quay.io/example/app --tag v1 --layers --case CASE-0001
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_common import DEFAULT_UA, _browser_headers  # noqa: E402 — also installs the egress proxy
from wp_net import fetch  # noqa: E402 — Android UA + proxy handling for every JSON/API call
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA lives in references/*.json

try:  # optional: zstd-compressed OCI layers (stdlib from Python 3.14)
    from compression import zstd as _zstd  # type: ignore
except Exception:
    _zstd = None

# --- reference DATA (RULE 3). The fallback is the conservative minimum: Docker Hub only, config
#     blob only (tiny layer caps), the five credential shapes audit.sh blocks, .env files only.
_FALLBACK = {
    "settings": {"timeout_seconds": 30, "page_size": 100, "max_repos": 100, "max_images": 1,
                 "max_tags": 10, "platform": {"os": "linux", "architecture": "amd64"},
                 "config_max_bytes": 2000000, "layer_max_bytes": 10485760,
                 "layers_total_max_bytes": 20971520, "member_max_bytes": 262144,
                 "max_members_per_layer": 20000, "max_history_cmds": 100},
    "registries": {"docker.io": {
        "aliases": ["docker.io", "index.docker.io", "registry-1.docker.io"],
        "registry": "https://registry-1.docker.io",
        "token": "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{ns}/{repo}:pull",
        "list": "https://hub.docker.com/v2/namespaces/{ns}/repositories?page_size={page_size}&page={page}",
        "tags": "https://hub.docker.com/v2/namespaces/{ns}/repositories/{repo}/tags?page_size={page_size}&page=1"}},
    "media_types": {"accept": ["application/vnd.oci.image.index.v1+json",
                               "application/vnd.docker.distribution.manifest.list.v2+json",
                               "application/vnd.oci.image.manifest.v1+json",
                               "application/vnd.docker.distribution.manifest.v2+json"],
                    "index": ["application/vnd.oci.image.index.v1+json",
                              "application/vnd.docker.distribution.manifest.list.v2+json"]},
    "identity_labels": {"source": ["org.opencontainers.image.source"],
                        "person": ["org.opencontainers.image.authors", "maintainer"],
                        "org": ["org.opencontainers.image.vendor"]},
    "member_paths": {"include": [r"(^|/)\.env(\.[\w.-]+)?$"], "exclude": [r"(^|/)node_modules/"]},
    "secret_patterns": {
        "stripe_key": {"regex": r"\b[sr]k_live_[A-Za-z0-9]{16,}", "group": 0},
        "aws_access_key_id": {"regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "group": 0},
        "github_token": {"regex": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "group": 0},
        "slack_token": {"regex": r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "group": 0},
        "private_key": {"regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "group": 0}},
    "secret_env_name": {"regex": r"(?i)(SECRET|TOKEN|PASSWORD|API_?KEY)", "min_len": 8,
                        "benign": [r"(?i)_(VERSION|SHA256)$"]},
    "placeholder_values": [r"^\$\{?[A-Za-z_]", r"(?i)example"],
    "caveats": {"identity": "LEAD only: a registry namespace or image label is often a personal "
                            "developer/contractor account — never an edge on this signal alone.",
                "secret": "FACT that a credential-shaped string is public; not validated, "
                          "never printed in full."},
}
_REFS = load_ref(ref_path(__file__, "container_registry.json"), _FALLBACK)
_S = {**_FALLBACK["settings"], **(_REFS["settings"] or {})}
TIMEOUT = int(_S["timeout_seconds"])
PAGE_SIZE = int(_S["page_size"])
MAX_REPOS = int(_S["max_repos"])
MAX_IMAGES = int(_S["max_images"])
MAX_TAGS = int(_S["max_tags"])
PLATFORM = dict(_S["platform"] or {"os": "linux", "architecture": "amd64"})
CONFIG_MAX = int(_S["config_max_bytes"])
LAYER_MAX = int(_S["layer_max_bytes"])
LAYERS_TOTAL_MAX = int(_S["layers_total_max_bytes"])
MEMBER_MAX = int(_S["member_max_bytes"])
MAX_MEMBERS = int(_S["max_members_per_layer"])
MAX_HISTORY = int(_S["max_history_cmds"])
REGISTRIES = _REFS["registries"]
ACCEPT = ", ".join(_REFS["media_types"].get("accept") or _FALLBACK["media_types"]["accept"])
INDEX_TYPES = frozenset(_REFS["media_types"].get("index") or _FALLBACK["media_types"]["index"])
ID_LABELS = {k: list(v or []) for k, v in _REFS["identity_labels"].items()}
_MP = _REFS["member_paths"]
MEMBER_INCLUDE = [re.compile(p, re.I) for p in (_MP.get("include") or [])]
MEMBER_EXCLUDE = [re.compile(p, re.I) for p in (_MP.get("exclude") or [])]
SECRET_PATTERNS = [(kind, re.compile(spec["regex"]), int(spec.get("group") or 0))
                   for kind, spec in _REFS["secret_patterns"].items()]
_EN = _REFS["secret_env_name"]
SECRET_ENV_NAME = re.compile(_EN.get("regex") or _FALLBACK["secret_env_name"]["regex"])
SECRET_ENV_MIN = int(_EN.get("min_len") or 8)
BENIGN_NAMES = [re.compile(p) for p in (_EN.get("benign") or [])]
PLACEHOLDERS = [re.compile(p) for p in _REFS["placeholder_values"]]
CAVEAT_IDENTITY = _REFS["caveats"].get("identity") or _FALLBACK["caveats"]["identity"]
CAVEAT_SECRET = _REFS["caveats"].get("secret") or _FALLBACK["caveats"]["secret"]

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_NOP_RE = re.compile(r"^/bin/sh -c #\(nop\)\s*")
_CHALLENGE_RE = re.compile(r'(\w+)="([^"]*)"')


class _RateLimited(Exception):
    """An HTTP 429 anywhere — the run stops and returns what it has."""

    def __init__(self, url, retry_after=None):
        super().__init__(url)
        self.url, self.retry_after = url, retry_after


class _Transport(Exception):
    """A network/transport failure (no HTTP status)."""


# ----------------------------------------------------------------------------- redaction / scan
def _preview(value):
    """First/last 3 chars of a value; short values are fully hidden (length only)."""
    v = str(value)
    if len(v) <= 8:
        return f"[{len(v)} chars]"
    return f"{v[:3]}…{v[-3:]}"


def _sha(value):
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def _placeholder(value):
    return any(p.search(value) for p in PLACEHOLDERS)


def _benign_name(name):
    return any(p.search(name) for p in BENIGN_NAMES)


def scan_text(text):
    """Secret-shaped values in `text` -> [(kind, value)], one per distinct value (vendor shapes win
    over the generic named_assignment). Placeholders are dropped only for the generic name-based
    match — a vendor shape is specific enough to report as-is. A private key's value is the whole
    PEM block when its END marker is present, so its sha256 identifies the key, not the header."""
    text = text or ""
    out, seen = [], set()
    for kind, rx, grp in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(grp) if grp <= (rx.groups or 0) else m.group(0)
            if not val:
                continue
            if kind == "private_key":
                end = text.find("-----END", m.end())
                if end != -1:
                    stop = text.find("-----", end + 8)
                    val = text[m.start():(stop + 5) if stop != -1 else end]
            if val in seen:
                continue
            if kind == "named_assignment" and (_placeholder(val) or _benign_name(m.group(1))):
                continue
            seen.add(val)
            out.append((kind, val))
    return out


def _secret(image, kind, value, path, layer_digest=None):
    return {"image": image, "layer_digest": layer_digest, "path": path, "kind": kind,
            "preview": _preview(value), "sha256": _sha(value)}


def _redact(text, values):
    for v in sorted(values, key=len, reverse=True):
        text = text.replace(v, _preview(v))
    return text


def _identity(itype, value, source, image=None):
    return {"type": itype, "value": value, "source": source, "image": image,
            "rung": "lead", "caveat": CAVEAT_IDENTITY}


def _person_identities(raw, source, image):
    """A `Name <mail>` / comma-separated authors string -> email and name leads."""
    out = []
    for email in _EMAIL_RE.findall(raw):
        out.append(_identity("email", email.lower(), source, image))
    rest = _EMAIL_RE.sub("", raw)
    for part in re.split(r"[,;]", rest):
        name = part.strip(" <>()\"'\t")
        if len(name) >= 2 and not name.lower().startswith(("http://", "https://")):
            out.append(_identity("name", name, source, image))
    return out


def scan_config(config, image_ref):
    """Pure: an image CONFIG blob (dict) -> {labels, source_repo_url, env_keys, history_cmds,
    cmd, entrypoint, created, author, secrets, identities}. Secret values are never returned."""
    cfg = (config or {}).get("config") or (config or {}).get("container_config") or {}
    labels = dict(cfg.get("Labels") or {})
    secrets, secret_vals = [], set()

    def add(kind, value, path):
        h = _sha(value)
        if any(s["sha256"] == h and s["path"] == path for s in secrets):
            return
        secret_vals.add(value)
        secrets.append(_secret(image_ref, kind, value, path))

    env_keys = []
    for item in cfg.get("Env") or []:
        name, _, val = str(item).partition("=")
        hits = [(k, v) for k, v in scan_text(val) if k != "named_assignment"]
        for kind, v in hits:
            add(kind, v, f"config:Env:{name}")
        flagged = bool(hits)
        if (not hits and SECRET_ENV_NAME.search(name) and not _benign_name(name)
                and len(val) >= SECRET_ENV_MIN and not _placeholder(val)):
            add("env_named_secret", val, f"config:Env:{name}")
            flagged = True
        env_keys.append({"name": name, "preview": _preview(val) if val else "", "secret": flagged})

    for key, val in labels.items():
        for kind, v in scan_text(f"{key}={val}"):
            add(kind, v, f"config:Label:{key}")

    history_cmds = []
    for h in (config or {}).get("history") or []:
        line = _NOP_RE.sub("", str(h.get("created_by") or "")).strip()
        if not line:
            continue
        for kind, v in scan_text(line):
            add(kind, v, "config:history")
        history_cmds.append(line)
    for cmd_field in ("Cmd", "Entrypoint"):
        for kind, v in scan_text(" ".join(cfg.get(cmd_field) or [])):
            add(kind, v, f"config:{cmd_field}")

    history_cmds = [_redact(c, secret_vals) for c in history_cmds[:MAX_HISTORY]]
    labels_out = {k: _redact(str(v), secret_vals) for k, v in labels.items()}

    identities, source_repo_url = [], None
    for key in ID_LABELS.get("source") or []:
        if labels.get(key):
            source_repo_url = source_repo_url or str(labels[key]).strip()
            identities.append(_identity("source_repo", str(labels[key]).strip(), f"label:{key}", image_ref))
    for key in ID_LABELS.get("person") or []:
        if labels.get(key):
            identities += _person_identities(str(labels[key]), f"label:{key}", image_ref)
    for key in ID_LABELS.get("org") or []:
        if labels.get(key):
            identities.append(_identity("org", str(labels[key]).strip(), f"label:{key}", image_ref))
    author = str((config or {}).get("author") or "").strip()
    if author:
        identities += _person_identities(author, "config:author", image_ref)

    return {"labels": labels_out, "source_repo_url": source_repo_url, "env_keys": env_keys,
            "history_cmds": history_cmds,
            "cmd": [_redact(str(c), secret_vals) for c in cfg.get("Cmd") or []],
            "entrypoint": [_redact(str(c), secret_vals) for c in cfg.get("Entrypoint") or []],
            "created": (config or {}).get("created"), "author": author or None,
            "os": (config or {}).get("os"), "architecture": (config or {}).get("architecture"),
            "secrets": secrets, "identities": identities}


def member_wanted(path):
    p = (path or "").lstrip("/")
    return (any(r.search(p) for r in MEMBER_INCLUDE)
            and not any(r.search(p) for r in MEMBER_EXCLUDE))


class _Capped(io.RawIOBase):
    """Read at most `cap` bytes from `raw`, then report EOF (the tar reader then stops)."""

    def __init__(self, raw, cap):
        self.raw, self.cap, self.n, self.hit_cap = raw, cap, 0, False

    def readable(self):
        return True

    def readinto(self, b):
        left = self.cap - self.n
        if left <= 0:
            self.hit_cap = True
            return 0
        chunk = self.raw.read(min(len(b), left))
        if not chunk:
            return 0
        b[:len(chunk)] = chunk
        self.n += len(chunk)
        return len(chunk)


def scan_layer_tar(fileobj, image_ref, layer_digest, media_type="", cap=None):
    """Pure-ish: stream a layer tarball from `fileobj` (gzip / plain / zstd), read members whose
    path matches the reference patterns, secret-scan them. Never raises. Returns {digest,
    bytes_read, truncated, members_seen, files[], secrets[], note?}."""
    cap = LAYER_MAX if cap is None else cap
    res = {"digest": layer_digest, "media_type": media_type or None, "bytes_read": 0,
           "truncated": False, "members_seen": 0, "files": [], "secrets": []}
    capped = _Capped(fileobj, cap)
    stream = io.BufferedReader(capped, 1 << 16)
    if "zstd" in (media_type or ""):
        if _zstd is None:
            res["note"] = "zstd layer skipped — compression.zstd unavailable (Python < 3.14)"
            return res
        stream = _zstd.ZstdFile(stream)
    seen = set()
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as tf:
            for ti in tf:
                res["members_seen"] += 1
                if res["members_seen"] > MAX_MEMBERS:
                    res["truncated"] = True
                    res["note"] = f"member cap {MAX_MEMBERS} reached"
                    break
                if not ti.isfile() or not member_wanted(ti.name):
                    continue
                fh = tf.extractfile(ti)
                data = fh.read(MEMBER_MAX) if fh else b""
                path = "/" + re.sub(r"^(\./)+", "", ti.name).lstrip("/")
                res["files"].append({"path": path, "size": ti.size,
                                     "partial": ti.size > MEMBER_MAX})
                if b"\x00" in data[:2048]:
                    if re.search(r"\.(p12|pfx|jks|keystore)$", path, re.I):
                        h = hashlib.sha256(data).hexdigest()
                        res["secrets"].append({"image": image_ref, "layer_digest": layer_digest,
                                               "path": path, "kind": "key_material_file",
                                               "preview": f"[binary {ti.size} bytes]", "sha256": h})
                    continue
                for kind, val in scan_text(data.decode("utf-8", "replace")):
                    key = (path, _sha(val))
                    if key in seen:
                        continue
                    seen.add(key)
                    res["secrets"].append(_secret(image_ref, kind, val, path, layer_digest))
    except (tarfile.TarError, EOFError, zlib.error, OSError, ValueError) as e:
        if capped.hit_cap:
            res["truncated"] = True
            res["note"] = f"layer read stopped at the {cap}-byte cap"
        else:
            res["note"] = f"tar read error: {type(e).__name__}: {e}"[:200]
    if capped.hit_cap:
        res["truncated"] = True
    res["bytes_read"] = capped.n
    return res


# ----------------------------------------------------------------------------- HTTP
def _get(url, headers=None):
    """fetch() wrapper -> (status, headers, body). 429 -> _RateLimited; transport -> _Transport."""
    try:
        _final, st, h, body = fetch(url, timeout=TIMEOUT, extra_headers=headers or {})
    except Exception as e:  # requests / urllib transport failure
        raise _Transport(f"{type(e).__name__}: {e}"[:300])
    if st == 429:
        raise _RateLimited(url, (h or {}).get("retry-after"))
    return st, h or {}, body or b""


def _get_json(url, headers=None):
    st, h, body = _get(url, {"Accept": "application/json", **(headers or {})})
    try:
        obj = json.loads(body) if st == 200 else None
    except ValueError:
        obj = None
    return st, h, obj


def _fill(template, **kw):
    return template.format(**{k: urllib.parse.quote(str(v), safe="/") for k, v in kw.items()})


class _Registry:
    """Anonymous OCI distribution client for one registry (token cache per repository)."""

    def __init__(self, key):
        self.key = key
        self.cfg = REGISTRIES.get(key) or {"registry": f"https://{key}"}
        self.base = self.cfg.get("registry") or f"https://{key}"
        self.tokens = {}

    def _token(self, repo, challenge=None):
        ns, _, name = repo.partition("/")
        urls = []
        if self.cfg.get("token"):
            urls.append(_fill(self.cfg["token"], ns=ns, repo=name))
        if challenge and challenge.lower().startswith("bearer"):
            p = dict(_CHALLENGE_RE.findall(challenge))
            if p.get("realm"):
                q = {k: v for k, v in (("service", p.get("service")),
                                       ("scope", p.get("scope") or f"repository:{repo}:pull")) if v}
                urls.append(p["realm"] + ("&" if "?" in p["realm"] else "?") + urllib.parse.urlencode(q))
        for u in urls:
            st, _h, obj = _get_json(u)
            tok = (obj or {}).get("token") or (obj or {}).get("access_token")
            if st == 200 and tok:
                self.tokens[repo] = tok
                return tok
        return None

    def get(self, repo, path, accept):
        """GET /v2/<repo>/<path> with token retry -> (status, headers, body)."""
        url = f"{self.base}/v2/{repo}/{path}"
        for attempt in (0, 1):
            hdr = {"Accept": accept, "Accept-Encoding": "identity"}
            if self.tokens.get(repo):
                hdr["Authorization"] = "Bearer " + self.tokens[repo]
            st, h, body = _get(url, hdr)
            if st == 401 and attempt == 0 and self._token(repo, h.get("www-authenticate")):
                continue
            return st, h, body
        return st, h, body

    def open_blob(self, repo, digest):
        """Open a blob as a stream (byte caps are applied by the reader) -> response | None."""
        url = f"{self.base}/v2/{repo}/blobs/{digest}"
        for attempt in (0, 1):
            hdr = _browser_headers(DEFAULT_UA)
            hdr.update({"Accept": "*/*", "Accept-Encoding": "identity"})
            req = urllib.request.Request(url, headers=hdr)
            if self.tokens.get(repo):  # never forwarded to the storage CDN on redirect
                req.add_unredirected_header("Authorization", "Bearer " + self.tokens[repo])
            try:
                return urllib.request.urlopen(req, timeout=TIMEOUT)
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    raise _RateLimited(url, e.headers.get("Retry-After") if e.headers else None)
                if e.code == 401 and attempt == 0 and self._token(
                        repo, (e.headers or {}).get("WWW-Authenticate")):
                    continue
                if e.code == 404:
                    return None
                raise _Transport(f"HTTP {e.code} on blob {digest}")
            except Exception as e:
                raise _Transport(f"{type(e).__name__}: {e}"[:300])
        return None


# ----------------------------------------------------------------------------- target parsing
def parse_target(raw, force_image=False):
    """`raw` -> {registry, namespace, repo, ref, kind} or {"error"}. Bare Hub names are a
    namespace unless they carry a tag/digest or `force_image`."""
    s = (raw or "").strip()
    s = re.sub(r"^[a-z]+://", "", s).rstrip("/")
    m = re.match(r"^hub\.docker\.com/(?:r|u|repository/docker|orgs)/(.+)$", s)
    if m:
        s = m.group(1)
    m = re.match(r"^hub\.docker\.com/_/([^/?#]+)", s)
    if m:
        s = "library/" + m.group(1)
    s = s.split("?")[0].split("#")[0]
    parts = [p for p in s.split("/") if p]
    if not parts:
        return {"error": f"no namespace or image in {raw!r}"}
    registry = "docker.io"
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host = parts.pop(0).lower()
        registry = next((k for k, c in REGISTRIES.items() if host in (c.get("aliases") or [k])), host)
    ref = None
    last = parts[-1]
    if "@" in last:
        last, ref = last.split("@", 1)
    elif ":" in last:
        last, ref = last.rsplit(":", 1)
    parts[-1] = last
    if len(parts) == 1 and not ref and not force_image:
        return {"registry": registry, "namespace": parts[0], "repo": None, "ref": None,
                "kind": "namespace"}
    if len(parts) == 1:
        if registry != "docker.io":
            return {"error": f"{raw!r}: an image on {registry} needs <namespace>/<name>"}
        parts = ["library"] + parts
    return {"registry": registry, "namespace": parts[0], "repo": "/".join(parts), "ref": ref,
            "kind": "image"}


def _image_ref(registry, repo, ref):
    sep = "@" if ref and ref.startswith("sha256:") else ":"
    return f"{registry}/{repo}{sep}{ref}" if ref else f"{registry}/{repo}"


# ----------------------------------------------------------------------------- namespace listing
def _hub_profile(ns):
    cfg = REGISTRIES.get("docker.io") or {}
    for kind in ("user", "org"):
        if not cfg.get(kind):
            continue
        st, _h, obj = _get_json(_fill(cfg[kind], ns=ns))
        if st == 200 and isinstance(obj, dict):
            keep = ("id", "uuid", "orgname", "username", "full_name", "company", "location",
                    "profile_url", "date_joined", "type", "badge")
            return {"endpoint": kind, **{k: obj.get(k) for k in keep if obj.get(k) not in (None, "")}}
    return None


def list_namespace(registry, ns):
    """-> (profile|None, repositories[], total|None). Raises _RateLimited / _Transport.

    Docker Hub refuses anonymous paging past ~100 items (HTTP 403 'pagination offset too large'),
    so the walk re-reads page 1.. under each reference `ordering` and unions the names — that
    reaches most of a few-hundred-repo namespace without an account. `total` is Hub's own count."""
    cfg = REGISTRIES.get(registry) or {}
    repos, profile, total = [], None, None
    if registry == "docker.io":
        profile = _hub_profile(ns)
        seen = set()
        orderings = [str(o) for o in (cfg.get("orderings") or [""])]
        for tmpl in [t for t in (cfg.get("list"), cfg.get("list_alt")) if t]:
            for ordering in orderings:
                page = 1
                while len(repos) < MAX_REPOS:
                    st, _h, obj = _get_json(_fill(tmpl, ns=ns, page=page, page_size=PAGE_SIZE,
                                                  ordering=ordering))
                    if st != 200 or not isinstance(obj, dict):
                        break                       # 403 offset cap / 404: next ordering
                    total = obj.get("count") if total is None else total
                    for r in obj.get("results") or []:
                        name = r.get("name")
                        if not name or name in seen:
                            continue
                        seen.add(name)
                        repos.append({
                            "registry": registry, "namespace": r.get("namespace") or ns, "name": name,
                            "ref": f"docker.io/{ns}/{name}", "description": r.get("description") or None,
                            "pull_count": r.get("pull_count"), "star_count": r.get("star_count"),
                            "last_updated": r.get("last_updated"),
                            "date_registered": r.get("date_registered"),
                            "is_private": r.get("is_private"),
                            "status": r.get("status_description") or r.get("status"),
                            "url": _fill(cfg.get("repo_page") or "", ns=ns, repo=name) or None})
                    if not obj.get("next"):
                        break
                    page += 1
                if len(repos) >= MAX_REPOS or (total is not None and len(repos) >= total) or not repos:
                    break                           # complete, capped, or namespace has nothing
            if repos:
                break
    elif registry == "quay.io" and cfg.get("list"):
        url = _fill(cfg["list"], ns=ns)
        while url and len(repos) < MAX_REPOS:
            st, _h, obj = _get_json(url)
            if st != 200 or not isinstance(obj, dict):
                break
            for r in obj.get("repositories") or []:
                name = r.get("name")
                if name and len(repos) < MAX_REPOS:
                    repos.append({
                        "registry": registry, "namespace": r.get("namespace") or ns, "name": name,
                        "ref": f"quay.io/{ns}/{name}", "description": r.get("description") or None,
                        "is_public": r.get("is_public"), "kind": r.get("kind"),
                        "popularity": r.get("popularity"), "last_modified": r.get("last_modified"),
                        "url": _fill(cfg.get("repo_page") or "", ns=ns, repo=name) or None})
            nxt = obj.get("next_page")
            url = (_fill(cfg["list"], ns=ns) + "&next_page=" + urllib.parse.quote(str(nxt))) if nxt else None
    elif registry == "ghcr.io":
        found_pages = {}
        rx = re.compile(r'href="(/(?:orgs|users)/[^/"]+/packages/container/package/([A-Za-z0-9._%-]+)'
                        r'|/[^/"]+/[^/"]+/pkgs/container/([A-Za-z0-9._%-]+))"')
        for tmpl in cfg.get("ghcr_pages") or []:
            base = _fill(tmpl, ns=ns)
            for page in range(1, 1 + max(1, MAX_REPOS // 10)):
                st, _h, body = _get(base + f"&page={page}", {"Accept": "text/html"})
                if st != 200:
                    break
                before = len(found_pages)
                for m in rx.finditer(body.decode("utf-8", "replace")):
                    n = urllib.parse.unquote(m.group(2) or m.group(3))
                    found_pages.setdefault(n, "https://github.com" + m.group(1))
                if len(found_pages) == before or len(found_pages) >= MAX_REPOS:
                    break                               # no new package on this page: done
            if found_pages:
                profile = {"endpoint": "github_packages_page", "url": base}
                break
        for n, page_url in list(found_pages.items())[:MAX_REPOS]:
            repos.append({"registry": registry, "namespace": ns, "name": n,
                          "ref": f"ghcr.io/{ns}/{n}", "url": page_url})
    else:
        raise _Transport(f"namespace listing is not supported for {registry} — pass an image ref")
    return profile, repos, total


def list_tags(reg, repo):
    """-> [{name, last_updated?, digest?}] newest first where the API orders them."""
    cfg = reg.cfg
    ns, _, name = repo.partition("/")
    if reg.key == "docker.io" and cfg.get("tags"):
        st, _h, obj = _get_json(_fill(cfg["tags"], ns=ns, repo=name, page_size=min(PAGE_SIZE, max(MAX_TAGS, 1))))
        if st == 200 and isinstance(obj, dict):
            return [{"name": t.get("name"), "last_updated": t.get("last_updated"),
                     "digest": t.get("digest")} for t in (obj.get("results") or []) if t.get("name")]
    if reg.key == "quay.io" and cfg.get("tags"):
        st, _h, obj = _get_json(_fill(cfg["tags"], ns=ns, repo=name, page_size=min(PAGE_SIZE, max(MAX_TAGS, 1))))
        if st == 200 and isinstance(obj, dict):
            return [{"name": t.get("name"), "last_updated": t.get("last_modified"),
                     "digest": t.get("manifest_digest")} for t in (obj.get("tags") or []) if t.get("name")]
    st, _h, body = reg.get(repo, "tags/list", "application/json")
    if st != 200:
        return []
    try:
        names = json.loads(body).get("tags") or []
    except ValueError:
        return []
    return [{"name": n} for n in reversed(names)]  # registry order is lexical; newest unknown


# ----------------------------------------------------------------------------- image inspection
def _pick_platform(index):
    mans = index.get("manifests") or []
    want_os, want_arch = PLATFORM.get("os"), PLATFORM.get("architecture")
    for m in mans:
        p = m.get("platform") or {}
        if p.get("os") == want_os and p.get("architecture") == want_arch:
            return m
    for m in mans:
        p = m.get("platform") or {}
        if p.get("os") not in (None, "unknown") and p.get("architecture") not in (None, "unknown"):
            return m
    return mans[0] if mans else None


def inspect_image(reg, repo, ref, layers=False, budget=None):
    """-> (image dict, secrets[], identities[]) or None when the manifest does not exist."""
    ref = ref or "latest"
    image_ref = _image_ref(reg.key, repo, ref)
    st, h, body = reg.get(repo, f"manifests/{ref}", ACCEPT)
    if st == 404:
        return None
    if st != 200:
        return {"ref": image_ref, "error": f"manifest HTTP {st}"}, [], []
    try:
        man = json.loads(body)
    except ValueError:
        return {"ref": image_ref, "error": "manifest is not JSON"}, [], []
    index_digest, platforms = None, None
    mt = man.get("mediaType") or (h.get("content-type") or "").split(";")[0]
    if mt in INDEX_TYPES or ("manifests" in man and "config" not in man):
        index_digest = h.get("docker-content-digest") or "sha256:" + hashlib.sha256(body).hexdigest()
        platforms = [f"{p.get('os')}/{p.get('architecture')}"
                     for p in ((m.get("platform") or {}) for m in man.get("manifests") or [])
                     if p.get("os") not in (None, "unknown")]   # unknown/unknown = attestations
        pick = _pick_platform(man)
        if not pick:
            return {"ref": image_ref, "error": "empty manifest index"}, [], []
        st, h, body = reg.get(repo, f"manifests/{pick['digest']}", ACCEPT)
        if st != 200:
            return {"ref": image_ref, "error": f"platform manifest HTTP {st}"}, [], []
        try:
            man = json.loads(body)
        except ValueError:
            return {"ref": image_ref, "error": "platform manifest is not JSON"}, [], []
    digest = h.get("docker-content-digest") or "sha256:" + hashlib.sha256(body).hexdigest()
    img = {"ref": image_ref, "digest": digest, "index_digest": index_digest, "platforms": platforms,
           "layers": [{"digest": l.get("digest"), "size": l.get("size"), "media_type": l.get("mediaType")}
                      for l in man.get("layers") or []]}
    if man.get("schemaVersion") == 1 or not (man.get("config") or {}).get("digest"):
        img["note"] = "schema-1 / config-less manifest — no config blob to read"
        return img, [], []
    cfg_digest = man["config"]["digest"]
    resp = reg.open_blob(repo, cfg_digest)
    if resp is None:
        img["error"] = "config blob 404"
        return img, [], []
    with resp:
        raw = resp.read(CONFIG_MAX + 1)
    if len(raw) > CONFIG_MAX:
        img["error"] = f"config blob larger than {CONFIG_MAX} bytes — not parsed"
        return img, [], []
    try:
        config = json.loads(raw)
    except ValueError:
        img["error"] = "config blob is not JSON"
        return img, [], []
    sc = scan_config(config, image_ref)
    secrets, identities = sc.pop("secrets"), sc.pop("identities")
    img.update({"config_digest": cfg_digest, **sc})
    if layers:
        img["layer_scan"] = []
        for layer in img["layers"]:
            if budget is not None and budget["used"] >= LAYERS_TOTAL_MAX:
                img["layer_scan"].append({"digest": layer["digest"], "skipped": "total byte cap reached"})
                continue
            cap = LAYER_MAX if budget is None else min(LAYER_MAX, LAYERS_TOTAL_MAX - budget["used"])
            lresp = reg.open_blob(repo, layer["digest"])
            if lresp is None:
                img["layer_scan"].append({"digest": layer["digest"], "skipped": "blob 404"})
                continue
            with lresp:
                ls = scan_layer_tar(lresp, image_ref, layer["digest"], layer.get("media_type") or "", cap)
            if budget is not None:
                budget["used"] += ls["bytes_read"]
            secrets += ls.pop("secrets")
            img["layer_scan"].append(ls)
    return img, secrets, identities


def _choose_tag(tags, wanted):
    names = [t["name"] for t in tags]
    if wanted:
        return wanted
    if "latest" in names:
        return "latest"
    return names[0] if names else "latest"


# ----------------------------------------------------------------------------- entry point
def registry_osint(target, force_image=False, tag=None, layers=False, max_images=None, max_tags=None):
    """Tri-state: dict | None (namespace/image does not exist) | {"error": …}."""
    t = parse_target(target, force_image)
    if t.get("error"):
        return t
    max_images = MAX_IMAGES if max_images is None else max(0, int(max_images))
    max_tags = MAX_TAGS if max_tags is None else max(0, int(max_tags))
    out = {"target": target, "registry": t["registry"], "namespace": t["namespace"],
           "kind": t["kind"], "profile": None, "repositories": [], "images": [], "secrets": [],
           "identities": [], "notes": [], "rate_limited": None,
           "caps": {"layers": bool(layers), "layer_max_bytes": LAYER_MAX,
                    "layers_total_max_bytes": LAYERS_TOTAL_MAX, "layer_bytes_read": 0},
           "caveats": {"identities": CAVEAT_IDENTITY, "secrets": CAVEAT_SECRET}}
    reg = _Registry(t["registry"])
    budget = {"used": 0}
    found = False
    try:
        if t["kind"] == "namespace":
            profile, repos, total = list_namespace(t["registry"], t["namespace"])
            out["profile"], out["repositories"] = profile, repos
            out["repositories_total"] = total if total is not None else len(repos)
            if total is not None and len(repos) < total:
                out["notes"].append(f"listed {len(repos)} of {total} repositories (anonymous "
                                    f"paging cap / max_repos {MAX_REPOS})")
            found = bool(profile or repos)
            if profile:
                src = f"{t['registry']}:profile"
                if profile.get("full_name"):
                    out["identities"].append(_identity("name", profile["full_name"], src))
                if profile.get("company"):
                    out["identities"].append(_identity("org", profile["company"], src))
                if profile.get("profile_url"):
                    out["identities"].append(_identity("url", profile["profile_url"], src))
            out["identities"].append(_identity("registry_namespace", f"{t['registry']}/{t['namespace']}",
                                               f"{t['registry']}:namespace"))
            ordered = sorted(repos, key=lambda r: str(r.get("last_updated") or r.get("last_modified") or ""),
                             reverse=True)
            targets = [(f"{r['namespace']}/{r['name']}", None, r) for r in ordered[:max_images]]
        else:
            targets = [(t["repo"], t["ref"], None)]
        for repo, ref, repo_row in targets:
            tags = list_tags(reg, repo) if (max_tags or not ref) else []
            chosen = ref or _choose_tag(tags, tag)
            res = inspect_image(reg, repo, chosen, layers=layers, budget=budget)
            if res is None:
                out["images"].append({"ref": _image_ref(reg.key, repo, chosen), "error": "manifest not found"})
                continue
            img, secrets, identities = res
            img["tags"] = tags[:max_tags]
            if repo_row is not None:
                repo_row["inspected_tag"] = chosen
            found = True
            out["images"].append(img)
            out["secrets"] += secrets
            out["identities"] += identities
    except _RateLimited as e:
        out["rate_limited"] = {"url": e.url, "retry_after": e.retry_after}
        out["notes"].append("HTTP 429 — run stopped; partial result")
        found = True
    except _Transport as e:
        if not found and not out["repositories"]:
            return {"error": str(e), "target": target}
        out["notes"].append(f"transport failure, partial result: {e}")
    except Exception as e:  # never raise: an unexpected payload shape becomes a note / error
        if not found and not out["repositories"]:
            return {"error": f"{type(e).__name__}: {e}"[:300], "target": target}
        out["notes"].append(f"unexpected {type(e).__name__}, partial result: {e}"[:300])
    out["caps"]["layer_bytes_read"] = budget["used"]
    if not found:
        return None
    seen, ids = set(), []
    for i in out["identities"]:
        k = (i["type"], str(i["value"]).lower())
        if k not in seen:
            seen.add(k)
            ids.append(i)
    out["identities"] = ids
    return out


def save_to_case(case_id, res):
    """Persist a result as cases/<id>/container/<slug>.json (facts/leads; nothing ingested as an
    edge). Only a dict without `error` is stored. Returns the path, or None."""
    if not case_id or not isinstance(res, dict) or res.get("error"):
        return None
    home = os.environ.get("INTEL_HOME") or ENGINE
    case_dir = os.path.join(home, "cases", case_id)
    if not os.path.isdir(case_dir):
        return None
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(res.get("target") or "target")).strip("_")
    out_dir = os.path.join(case_dir, "container")
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, slug + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        return path
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Passive public container-registry OSINT "
                                             "(Docker Hub / GHCR / Quay / OCI v2).")
    ap.add_argument("target", help="namespace (example | ghcr.io/owner | quay.io/ns) or image "
                                   "ref (ns/img:tag, registry/ns/img@sha256:…)")
    ap.add_argument("--image", action="store_true", help="treat a bare Docker Hub name as an image "
                                                         "(alpine -> library/alpine)")
    ap.add_argument("--tag", help="tag to inspect (default: the ref's tag, else latest, else newest)")
    ap.add_argument("--layers", action="store_true", help="also stream layer blobs (byte-capped) "
                                                          "and secret-scan config-like files")
    ap.add_argument("--max-images", type=int, default=None,
                    help=f"namespace mode: repositories whose config is inspected (default {MAX_IMAGES}; 0 = list only)")
    ap.add_argument("--max-tags", type=int, default=None, help=f"tags returned per image (default {MAX_TAGS})")
    ap.add_argument("--case", help="save the result to cases/<id>/container/")
    ap.add_argument("--json", action="store_true", help="compact JSON (default: pretty-printed)")
    a = ap.parse_args()
    res = registry_osint(a.target, a.image, a.tag, a.layers, a.max_images, a.max_tags)
    if res is None:
        res = {"target": a.target, "result": None,
               "note": "no such namespace / image on the registry (or nothing public)"}
    elif a.case:
        p = save_to_case(a.case, res)
        if p:
            res["saved"] = os.path.relpath(p, os.environ.get("INTEL_HOME") or ENGINE)
    print(json.dumps(res, indent=None if a.json else 2, ensure_ascii=False))
    return 1 if isinstance(res, dict) and res.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
