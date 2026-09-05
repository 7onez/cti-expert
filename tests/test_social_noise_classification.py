#!/usr/bin/env python3
"""RULE 5 classification check — social indicators, plus the mandated DNS pair.

CLAUDE.md RULE 5: any change to noise_filters.py ships with a classification check covering at
least one managed provider and one self-hosted nameserver. This adds the social branch that
is_noise_indicator previously did not dispatch on at all.

Why it matters in both directions:
  - TOO LOOSE: a bare `facebook.com` scraped as a "social handle" bridges any two sites that
    both link to Facebook. That is nearly every site, so a cluster built on it names an
    innocent party.
  - TOO TIGHT: matching only the HOST would discard `t.me/some_channel` — a real operator
    channel and often the single best pivot on a scam estate. Losing that is worse than the
    noise it removes.

Pure: no network, no KB.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "intel_engine" / "tools" / "kb"))
spec = importlib.util.spec_from_file_location(
    "noise_filters", ROOT / "intel_engine" / "tools" / "kb" / "noise_filters.py")
nf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nf)

FAIL = []


def want(value, expected, why):
    got = nf.is_noise_indicator(value)
    if got != expected:
        FAIL.append(f"{value!r}: got noise={got}, want {expected} — {why}")


# ── the RULE 5 mandated pair: managed provider vs self-hosted nameserver ───────────────
want("ns:ns1.cloudflare.com", True,
     "delegation to a MANAGED provider is shared infrastructure, not an owner link")
want("ns:ns1.operator-host.example", False,
     "a nameserver the operator runs themselves IS attribution-grade — you cannot point a "
     "domain at ns1.<their-host> without controlling that zone")

# ── social: bare platform apex is noise ───────────────────────────────────────────────
for apex in ("social:telegram:t.me", "social:facebook:facebook.com",
             "social:facebook:www.facebook.com", "social:twitter:x.com",
             "social:instagram:instagram.com", "social:youtube:www.youtube.com",
             "social:facebook:facebook.com/"):
    want(apex, True, "a bare platform apex names no account")

# ── social: a real account is NOT noise (the expensive direction) ──────────────────────
for real in ("social:telegram:t.me/some_channel", "social:telegram:https://t.me/+InviteCode",
             "social:twitter:x.com/someuser", "social:youtube:SomeChannelName",
             "social:whatsapp:wa.me/840000000", "social:facebook:facebook.com/some.page"):
    want(real, False, "a real account/channel must survive — it is often the best pivot")

# ── social: static assets and template placeholders stay noise ────────────────────────
want("social:facebook:icon.png", True, "a static asset is not a handle")
want("social:twitter:{username}", True, "an unsubstituted template placeholder is not a handle")

# ── the branch must exist at all: a malformed social id is noise, not a silent False ───
want("social:", True, "a social indicator with no handle segment carries nothing")

# ── unrelated indicator kinds must be unaffected by this change ───────────────────────
want("favicon:123456789", False, "an ordinary favicon hash is not noise by default")
want("google_analytics_ga4:G-XXXXXXXXXX", False, "a well-formed GA4 id is a real indicator")
want("google_analytics_ga4:g-recaptcha", True, "a mis-extracted web-component class is not a GA4 id")

if FAIL:
    for f in FAIL:
        print(f"FAIL: {f}", file=sys.stderr)
    sys.exit(1)
print(f"social/DNS noise classification: {21} checks passed")
