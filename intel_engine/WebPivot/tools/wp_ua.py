#!/usr/bin/env python3
"""
wp_ua.py — the ONE source of the default User-Agent.

POLICY (project decision)
-------------------------
Every request this toolkit sends presents as Android Chrome: target pages, archives and vendor /
index APIs alike. The strings are reference DATA (`references/fetch_profile.json -> ua_pool`)
because a browser ships a new major version every few weeks and a UA advertising a stale one is
itself a bot tell. `DEFAULT_UA` is the pool's first entry; `UA_POOL` is what a multi-page crawl
rotates through.

A different string is sent only where the SERVICE requires one. Those exceptions are listed in
`fetch_profile.json -> ua_exceptions`, each owned by the module named there — never add a
User-Agent literal anywhere else.

SIDE-EFFECT FREE ON PURPOSE
---------------------------
Importing `wp_common` installs the process-global egress proxy and the urlopen timeout floor.
This module does neither, so a standalone tool or a root script can read the string without
changing how it reaches the network. `wp_common` re-exports both names from here.

Stdlib only. Importable from any component (`sys.path` must hold this directory).
"""
import sys

__all__ = ["DEFAULT_UA", "UA_POOL"]

# Conservative minimum: ONE current Android Chrome string — rotation is off, the policy holds.
_UA_FALLBACK = {"ua_pool": ["Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"]}

try:
    from wp_refs import load_ref, ref_path
    _UA_REF = load_ref(ref_path(__file__, "fetch_profile.json"), _UA_FALLBACK)
except Exception as _e:  # noqa: BLE001 — a missing loader degrades to the fallback, never to no UA
    print(f"[wp_ua] WARNING: fetch_profile.json not read ({type(_e).__name__}); "
          "using the single embedded Android User-Agent.", file=sys.stderr)
    _UA_REF = _UA_FALLBACK

UA_POOL = [u for u in (_UA_REF.get("ua_pool") or []) if isinstance(u, str) and u.strip()] \
    or list(_UA_FALLBACK["ua_pool"])
DEFAULT_UA = UA_POOL[0]
