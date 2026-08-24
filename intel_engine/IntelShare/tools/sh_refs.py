#!/usr/bin/env python3
"""
sh_refs.py — the loader every module uses to read its tunable REFERENCE DATA out of
`references/*.json` instead of hardcoding it in Python (contributor RULE 3).

WHY THIS EXISTS
---------------
An analyst must be able to extend a denylist, a provider registry or a threshold WITHOUT
editing Python and without a redeploy. Code holds the *matching logic*; the values it matches
against are DATA. Before this loader existed the same denylists were pasted into five or six
modules and drifted apart — one module knew about a privacy proxy the next one did not, so the
same false cluster came back through whichever module was stale.

THE CONTRACT
------------
A reference file is a JSON object. Keys beginning with `_` are documentation and are ignored.
Every other key is a GROUP, in one of three shapes:

    "group": {"_comment": "...", "values": [ ... ]}        -> loaded as a list
    "group": {"_comment": "...", "entries": { ... }}       -> loaded as a dict (order preserved)
    "group": {"_comment": "...", "min": 7, "max": 15}      -> loaded as a dict of scalars

A bare list or object is accepted too, so an older file without the wrapper still loads.

FAILURE MODE — NEVER SILENT
---------------------------
`load_ref()` takes the caller's minimal embedded FALLBACK. If the file is missing, unparseable,
or missing a group, the fallback is used for exactly what is broken and a WARNING goes to stderr.
It never fails open silently: a filter that quietly returns False everywhere manufactures false
clusters, which is worse than crashing.

VENDORED ON PURPOSE
-------------------
WebPivot / BinaryPivot / tools-kb each ship an identical copy of this loader, because the skills
are imported onto other machines standalone and must not depend on a repo-root package.
`tests/test_references.py` asserts the copies stay byte-identical.
"""
import copy
import json
import os
import sys

__all__ = ["ref_path", "load_ref"]


def ref_path(module_file: str, name: str) -> str:
    """Absolute path of the reference file `name` for the module containing `module_file`.

    Looks for a `references/` directory beside the module first (`tools/kb/references/…`), then
    one level up (`WebPivot/tools/*.py` -> `WebPivot/references/…`), so every layout in the repo
    resolves with the same call: `ref_path(__file__, "noise_filters.json")`."""
    here = os.path.dirname(os.path.abspath(module_file))
    candidates = [os.path.join(here, "references", name),
                  os.path.normpath(os.path.join(here, os.pardir, "references", name))]
    for c in candidates:
        if os.path.exists(c):
            return c
    for c in candidates:                       # not created yet — name the plausible location
        if os.path.isdir(os.path.dirname(c)):
            return c
    return candidates[0]


def _group(node, default):
    """One GROUP -> its Python value. See THE CONTRACT above."""
    if isinstance(node, dict):
        if isinstance(node.get("values"), list):
            return list(node["values"])
        if isinstance(node.get("entries"), dict):
            return {k: v for k, v in node["entries"].items() if not k.startswith("_")}
        return {k: v for k, v in node.items() if not k.startswith("_")}
    if isinstance(node, list):
        return list(node)
    return copy.deepcopy(default)


def load_ref(path: str, fallback: dict) -> dict:
    """Read `path` and return {group: value} for every key in `fallback`, plus any extra groups
    the file defines. Anything missing or malformed falls back to `fallback` WITH a stderr
    warning — see FAILURE MODE above."""
    tag = os.path.basename(path)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if not isinstance(doc, dict):
            raise ValueError("top level is not a JSON object")
    except Exception as exc:
        print(f"[refs] WARNING: could not load {path} ({exc}); using the minimal embedded "
              f"fallback — this module's coverage is REDUCED. Fix the file, do not ignore this.",
              file=sys.stderr)
        return copy.deepcopy(fallback)

    out, missing = {}, []
    for key, default in fallback.items():
        node = doc.get(key)
        if node is None:
            missing.append(key)
            out[key] = copy.deepcopy(default)
        else:
            out[key] = _group(node, default)
    for key, node in doc.items():              # groups the file adds beyond the fallback
        if not key.startswith("_") and key not in out:
            out[key] = _group(node, None)
    if missing:
        print(f"[refs] WARNING: {tag} is missing group(s) {', '.join(sorted(missing))}; "
              f"using the embedded fallback for those.", file=sys.stderr)
    return out
