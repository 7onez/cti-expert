#!/usr/bin/env python3
"""
en_refs.py — the Engage skill's copy of the reference-data loader (contributor RULE 3).

Byte-identical to WebPivot/tools/wp_refs.py from `import copy` down (tests/test_references.py
asserts this). It is a SEPARATE MODULE NAME on purpose: Engage is imported standalone onto other
machines, so it cannot depend on a repo-root package, and `wp_refs`/`en_refs` may both land on
sys.path in one process, where a shared `refs.py` would collide. See wp_refs.py for the full
contract, failure mode, and why the copies exist.
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
