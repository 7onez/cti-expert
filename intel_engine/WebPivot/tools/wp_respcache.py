"""wp_respcache — a cross-CASE on-disk cache for the few vendor answers that are safe to reuse.

wp_casememo stops one case paying twice for the same answer. This module does the same ACROSS
cases, for endpoints listed in references/response_cache.json and for nothing else:

  lookup(provider, action, query, variant="")            -> Hit(value, observed_at, empty) | None
  store(provider, action, query, value, empty=False,
        variant="", subject_time=None)                   -> True when written

WHAT MAY BE LISTED
  Only an answer that never becomes a dated sighting, or that describes something that no longer
  changes. The knowledge base dates every fact from the raw file it was read from, so a cached
  "this host is in the index today" would be ingested as observed today when it was really
  observed when the cache was filled. A count that only sizes a proposal, and the verdict of a
  scan that finished days ago, are safe; a live search is not. Do not add one here.

RULES
  * An endpoint with no policy entry is never cached (the fallback policy is empty).
  * No case scope -> no cache. The store lives beside the case store
    (<home>/cache/vendor/, from $WP_CASE_DIR = <home>/cases/<id>), exactly as wp_casememo needs
    a case directory. A handler or test with no case writes and reads nothing; a test with a
    temporary case store gets a temporary cache. $CTI_RESPONSE_CACHE_DIR overrides the location.
  * Callers decide WHICH answers are safe to keep: the count probe keeps only a count above the
    auto-run threshold (a smaller one decides that a pivot runs unapproved, so it is asked fresh).
  * CTI_RESPONSE_CACHE=0 turns lookups and writes off for the process.
  * An answer is kept `ttl_hours`; an EMPTY one `empty_ttl_hours` (it may fill in). A failed call
    is never stored - the caller only calls store() after a real answer.
  * `min_subject_age_hours`: the thing described (a scan) must be at least that old, by the
    vendor's own timestamp, before its answer is kept; an unknown age is too young.
  * Every entry keeps `observed_at`, the time the vendor really answered.

Storage is wp_casememo's (same keying, same atomic write); nothing here raises.
"""
import collections
import datetime
import hashlib
import os

import wp_casememo
from wp_refs import ref_path, load_ref  # noqa — lifetimes are reference DATA

SWITCH_ENV = "CTI_RESPONSE_CACHE"
DIR_ENV = "CTI_RESPONSE_CACHE_DIR"

# Conservative minimum: nothing is cached when the policy file is unreadable.
_FALLBACK = {"endpoints": {}}
_REF = load_ref(ref_path(__file__, "response_cache.json"), _FALLBACK)
ENDPOINTS = {str(k): v for k, v in (_REF.get("endpoints") or {}).items() if isinstance(v, dict)}

Hit = collections.namedtuple("Hit", "value observed_at empty")


def enabled() -> bool:
    return os.environ.get(SWITCH_ENV, "").strip().lower() not in ("0", "false", "no", "off")


def policy(provider, action):
    """The endpoint's policy dict, or None when it is not listed (= never cached)."""
    p = ENDPOINTS.get(f"{provider}.{action}")
    try:
        return p if p and float(p.get("ttl_hours") or 0) > 0 else None
    except (TypeError, ValueError):
        return None


def root(case_dir=None):
    """The cache directory for this process, or '' when there is no case scope."""
    explicit = os.environ.get(DIR_ENV)
    if explicit:
        return explicit
    cd = case_dir or wp_casememo.case_dir() or ""
    if not cd:
        return ""
    cd = os.path.abspath(cd)
    cases = os.path.dirname(cd)
    if os.path.basename(cases) != "cases":
        return ""
    return os.path.join(os.path.dirname(cases), "cache", "vendor")


def variant_for(secret) -> str:
    """The cache variant for a call made with this API key: `keyless`, or a short fingerprint of
    the key - never the key. Two keys (or a key and no key) can see different data, so their
    answers are stored apart."""
    if not secret:
        return "keyless"
    return "key-" + hashlib.sha256(str(secret).encode("utf-8")).hexdigest()[:10]


def _key(query, variant):
    return f"{variant}|{str(query).strip()}"


def _parse(stamp):
    if not isinstance(stamp, str) or not stamp.strip():
        return None
    try:
        t = datetime.datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _hours(pol, name, default):
    try:
        return float(pol.get(name, default))
    except (TypeError, ValueError):
        return float(default)


def lookup(provider, action, query, variant="", case_dir=None, now=None):
    """The stored answer while it is inside its lifetime, else None."""
    pol = policy(provider, action)
    d = root(case_dir)
    if not (pol and d and enabled() and str(query or "").strip()):
        return None
    doc = wp_casememo.get(f"{provider}.{action}", _key(query, variant), cdir=d)
    if not isinstance(doc, dict) or "answer" not in doc:
        return None
    seen = _parse(doc.get("observed_at"))
    if seen is None:
        return None
    ttl = _hours(pol, "empty_ttl_hours", 0) if doc.get("empty") else _hours(pol, "ttl_hours", 0)
    age = ((now or _now()) - seen).total_seconds() / 3600.0
    if ttl <= 0 or age < 0 or age > ttl:
        return None
    return Hit(doc["answer"], doc["observed_at"], bool(doc.get("empty")))


def store(provider, action, query, value, empty=False, variant="", subject_time=None,
          case_dir=None, now=None):
    """Keep a REAL answer. Returns True when written; never raises."""
    pol = policy(provider, action)
    d = root(case_dir)
    if not (pol and d and enabled() and str(query or "").strip()):
        return False
    now = now or _now()
    min_age = _hours(pol, "min_subject_age_hours", 0)
    if min_age > 0:
        subject = _parse(subject_time)
        if subject is None or (now - subject).total_seconds() / 3600.0 < min_age:
            return False
    if empty and _hours(pol, "empty_ttl_hours", 0) <= 0:
        return False
    return wp_casememo.put(f"{provider}.{action}", _key(query, variant),
                           {"answer": value, "empty": bool(empty),
                            "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}, cdir=d)
