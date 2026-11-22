#!/usr/bin/env python3
"""build_yamato_index.py — rebuild references/hunt_rules_yamato.json, the LINK-ONLY index of
Yamato Security's detection content, from local clones. Stdlib only; deterministic (same clones,
same commits, same arguments -> byte-identical output).

    python3 build_yamato_index.py [--hayabusa-rules DIR] [--suzaku-rules DIR] [--senrigan DIR]
                                  [--per-technique N] [--retrieved YYYY-MM-DD] [--out PATH]

Each clone is read at its HEAD commit through `git ls-tree` / `git cat-file --batch`, never from
the working tree or README text, so the index matches the pinned commit exactly.

What is copied: rule METADATA only (title, Sigma id, level, logsource, author, ATT&CK tags, path)
and, for Senrigan (AGPL-3.0), hunt names, severities, ATT&CK ids and the telemetry each hunt reads
(the CloudTrail eventSource, or the VPC Flow Log columns a VPC-flow hunt requires). Never a
`detection:` block, condition, selection value, SQL or prompt text.
A Sigma correlation file holds several `---`-separated documents (the correlation rule plus its
base rules); every document with an `id` is indexed as its own rule ref (`kind: correlation` or
`kind: base`, same path and URL). The YAML reader is a minimal line-based one for the top-level
keys above; a file it cannot read is skipped and counted.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "references", "hunt_rules_yamato.json")
GH = "https://github.com/Yamato-Security/"
RETRIEVED = "2026-11-16"
# N rule refs per technique per source. 5 keeps the file under ~1.5 MB alongside the full Sigma-id
# list (every indexed rule stays a valid hunt_package_ref) and still shows the strongest
# (critical/high) rules for most techniques; the rest sit behind the per-directory counts.
PER_TECHNIQUE = 5
LEVELS = ["critical", "high", "medium", "low", "informational"]
EXCLUDED_DIRS = ("deprecated", "unsupported")  # path segments Hayabusa/Suzaku do not load by default
ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
ATTACK_ID = re.compile(r"T\d{4}(\.\d{3})?")
AWS_TTC_ID = re.compile(r"T\d{4}(\.[A-Z]\d{3})")   # AWS Threat Technique Catalog extension ids
DRL = "DRL 1.1: keep the rule author on any shared rule or match"

RULE_SOURCES = {
    "hayabusa-rules": {
        "license": "Detection Rule License (DRL) 1.1",
        "rule_roots": ["hayabusa", "sigma"],
        "runs_with": [
            {"tool": "Hayabusa", "url": GH + "hayabusa", "license": "AGPL-3.0",
             "data": "Windows event logs (.evtx)"},
            {"tool": "Takajo", "url": GH + "takajo", "license": "AGPL-3.0",
             "data": "Hayabusa results (timelines)"}],
    },
    "suzaku-rules": {
        "license": "Detection Rule License (DRL) 1.1",
        "rule_roots": ["sigma", "suzaku"],
        "runs_with": [
            {"tool": "Suzaku", "url": GH + "suzaku", "license": "AGPL-3.0",
             "data": "cloud logs: AWS CloudTrail, Azure, Microsoft 365, Google Workspace"}],
    },
}
# path -> (id prefix, dataset, telemetry prefix). CloudTrail hunts list the eventSource values their
# SQL filters on; VPC-flow hunts list the columns their `requires` contract declares.
HUNT_FILES = {"agent/builtin_hunts.yaml": ("builtin", "CloudTrail events loaded into Senrigan", "cloudtrail"),
              "agent/suzaku_timeline_hunts.yaml": ("timeline", "a Suzaku aws-ct-timeline result", "cloudtrail"),
              "agent/vpc_flow_hunts.yaml": ("vpcflow", "VPC Flow Logs loaded into Senrigan", "vpcflow")}
TELEMETRY_FALLBACK = {"cloudtrail": "cloudtrail/any", "vpcflow": "flow/session"}


def git(clone, *args, data=None):
    return subprocess.run(["git", "-C", clone, *args], input=data, capture_output=True,
                          check=True).stdout


def head(clone):
    return git(clone, "rev-parse", "HEAD").decode().strip()


def read_blobs(clone, sha, paths):
    """{path: text} for every path at sha via one `git cat-file --batch`."""
    out = git(clone, "cat-file", "--batch",
              data="".join(f"{sha}:{p}\n" for p in paths).encode())
    blobs, i = {}, 0
    for p in paths:
        nl = out.index(b"\n", i)
        hdr = out[i:nl].split()
        if len(hdr) < 3 or hdr[1] != b"blob":
            blobs[p], i = None, nl + 1
            continue
        size = int(hdr[2])
        blobs[p] = out[nl + 1:nl + 1 + size].decode("utf-8", "replace")
        i = nl + 1 + size + 1
    return blobs


def blob_url(repo, sha, path, line=None):
    return f"{GH}{repo}/blob/{sha}/{urllib.parse.quote(path)}" + (f"#L{line}" if line else "")


def tree_url(repo, sha, path):
    return f"{GH}{repo}/tree/{sha}/{urllib.parse.quote(path)}"


def scalar(v):
    """A top-level YAML scalar: strip a trailing comment and one level of quotes."""
    v = v.strip()
    if v[:1] in ("'", '"') and v[-1:] == v[:1] and len(v) >= 2:
        q = v[0]
        v = v[1:-1]
        return v.replace("''", "'") if q == "'" else v.replace('\\"', '"')
    return re.sub(r"\s+#.*$", "", v).strip()


def split_docs(text):
    """The YAML documents of a rule file (split on `---` lines), dropping empty / comment-only ones."""
    docs, cur = [], []
    for raw in text.lstrip("\ufeff").splitlines():
        if raw.strip() == "---":
            docs.append(cur)
            cur = []
        else:
            cur.append(raw)
    docs.append(cur)
    return [d for d in docs if any(r.strip() and not r.lstrip().startswith("#") for r in d)]


def parse_rule(lines):
    """Top-level title/id/level/author/status, `tags` list, `logsource` map and kind (`detection` or
    `correlation`) of ONE Sigma document. Returns None when it is not a readable rule: no title or
    id, or neither a `detection` block with a logsource nor a `correlation` block (a correlation's
    logsource may sit in its base rules)."""
    rule, tags, logsource, cur = {}, [], {}, None
    kind = ""
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            m = re.match(r"^([A-Za-z_][\w-]*):(.*)$", raw)
            if not m:
                cur = None
                continue
            key, val = m.group(1), m.group(2)
            cur = key
            if key in ("detection", "correlation"):   # presence only; the block is never read
                kind = kind or key
            elif key in ("title", "id", "level", "author", "status") and val.strip():
                if val.strip()[:1] in ("|", ">"):
                    return None
                rule[key] = scalar(val)
            elif key == "tags" and val.strip().startswith("["):
                tags += [scalar(t) for t in val.strip()[1:-1].split(",") if t.strip()]
            continue
        if cur == "tags":
            m = re.match(r"^\s+-\s*(.+)$", raw)
            if m:
                tags.append(scalar(m.group(1)))
        elif cur == "logsource":
            m = re.match(r"^\s+(product|service|category):\s*(.*)$", raw)
            if m and m.group(2).strip():
                logsource[m.group(1)] = scalar(m.group(2))
    if not (rule.get("title") and rule.get("id")
            and (kind == "correlation" or (kind == "detection" and logsource))):
        return None
    rule["tags"], rule["logsource"], rule["kind"] = tags, logsource, kind
    return rule


def parse_file(text):
    """[rule] for every document carrying a top-level `id`, or None when the file has none or any
    such document is unreadable. In a file holding a correlation, each rule gets `kind`
    `correlation` or `base`; a plain rule file's single rule gets no kind."""
    docs = [d for d in split_docs(text) if any(re.match(r"^id:", r) for r in d)]
    rules = [parse_rule(d) for d in docs]
    if not rules or None in rules:
        return None
    corr = any(r["kind"] == "correlation" for r in rules)
    for r in rules:
        k = r.pop("kind")
        if corr:
            r["kind"] = "correlation" if k == "correlation" else "base"
    return rules


def level_rank(level):
    return LEVELS.index(level) if level in LEVELS else len(LEVELS)


def logsource_key(ls):
    return "/".join(ls.get(k, "-") for k in ("product", "service", "category"))


def index_rules(repo, clone, n):
    sha = head(clone)
    roots = RULE_SOURCES[repo]["rule_roots"]
    paths = sorted(p for p in git(clone, "ls-tree", "-r", "--name-only", sha).decode().splitlines()
                   if p.endswith((".yml", ".yaml")) and p.split("/", 1)[0] in roots)
    blobs = read_blobs(clone, sha, paths)
    excluded = {d: 0 for d in EXCLUDED_DIRS}
    unreadable, duplicates, untagged, rule_ids, per_tech = [], [], {}, set(), {}
    corr = {"files": [], "correlation_docs": 0, "base_docs": 0, "correlation_untagged": 0}
    for p in paths:
        seg = set(p.split("/")[:-1])
        hit = next((d for d in EXCLUDED_DIRS if d in seg), None)
        if hit:
            excluded[hit] += 1
            continue
        rules = parse_file(blobs[p]) if blobs[p] is not None else None
        if rules is None:
            unreadable.append(p)
            continue
        if "kind" in rules[0]:
            corr["files"].append(p)
        for rule in rules:
            kind = rule.get("kind")
            if kind:
                corr[f"{kind}_docs"] += 1
            if rule["id"] in rule_ids:
                duplicates.append(p)
            rule_ids.add(rule["id"])
            techs = sorted({m.group(1).upper() for t in rule["tags"] for m in [ATTACK_TAG.match(t)] if m})
            if not techs:              # a correlation inherits no tag from its base rules, nor they from it
                k = logsource_key(rule["logsource"])
                untagged[k] = untagged.get(k, 0) + 1
                if kind == "correlation":
                    corr["correlation_untagged"] += 1
                continue
            ref = {"id": rule["id"], "title": rule["title"], "level": rule.get("level", ""),
                   "logsource": rule["logsource"], "author": rule.get("author", ""), "path": p,
                   "url": blob_url(repo, sha, p)}
            if kind:
                ref["kind"] = kind
            for t in techs:
                per_tech.setdefault(t, []).append(ref)
    techniques = {}
    for t, refs in per_tech.items():
        refs = sorted(refs, key=lambda r: (level_rank(r["level"]), r["path"]))
        entry = {"count": len(refs), "rules": refs[:n]}
        if len(refs) > n:                  # the rest: every directory holding this technique's rules
            dirs = {}
            for r in refs:
                d = r["path"].rsplit("/", 1)[0]
                dirs[d] = dirs.get(d, 0) + 1
            entry["dirs"] = dict(sorted(dirs.items()))
        techniques[t] = entry
    indexed = len(rule_ids) + len(duplicates)
    meta = {k: v for k, v in RULE_SOURCES[repo].items()}
    meta.update(repo=GH + repo, pinned_commit=sha, retrieved=None, attribution=DRL,
                tree_url=tree_url(repo, sha, ""), rules_indexed=indexed,
                rules_tagged=indexed - sum(untagged.values()),
                untagged=dict(sorted(untagged.items())), excluded=excluded,
                unreadable=len(unreadable), unreadable_paths=unreadable,
                duplicate_id_paths=duplicates, correlation=corr, rule_ids=sorted(rule_ids))
    return meta, techniques


def slug(label):
    s = re.sub(r"\\[Uu][0-9a-fA-F]{4,8}", " ", label)
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:60].rstrip("-")


def clean_label(label):
    s = re.sub(r"\\[Uu][0-9a-fA-F]{4,8}", "", label)
    return re.sub(r"\s+", " ", re.sub(r"[^\x20-\x7e]", "", s)).strip()


def event_sources(sql):
    found = set(re.findall(r"event_source\s*=\s*'([^']+)'", sql))
    for grp in re.findall(r"event_source\s+IN\s*\(([^)]*)\)", sql, re.I):
        found.update(re.findall(r"'([^']+)'", grp))
    return sorted(found)


def parse_hunts(text):
    """[{line, label, severity, tids, requires, sql}] for each top-level `- category:` list item."""
    items, cur, block = [], None, None
    for i, raw in enumerate(text.splitlines(), 1):
        if raw.startswith("- category:"):
            cur = {"line": i, "label": "", "severity": "", "tids": [], "requires": [], "sql": []}
            items.append(cur)
            block = None
            continue
        if cur is None:
            continue
        m = re.match(r"^  ([a-z_]+):(.*)$", raw)
        if m:
            block, val = m.group(1), m.group(2).strip()
            if block == "label":
                cur["label"] = scalar(val)
            elif block == "severity":
                cur["severity"] = scalar(val)
            elif block == "requires" and val.startswith("["):
                cur["requires"] += [scalar(c) for c in val[1:-1].split(",") if c.strip()]
            continue
        if block == "techniques":
            m = re.match(r"^\s+-?\s*tid:\s*(.+)$", raw)
            if m:
                cur["tids"].append(scalar(m.group(1)))
        elif block == "requires":
            m = re.match(r"^\s+-\s*(.+)$", raw)
            if m:
                cur["requires"].append(scalar(m.group(1)))
        elif block == "sql":
            cur["sql"].append(raw)
    return items


def index_senrigan(clone):
    sha = head(clone)
    blobs = read_blobs(clone, sha, list(HUNT_FILES))
    hunts, seen, by_file = [], set(), {}
    for path, (kind, dataset, tele) in HUNT_FILES.items():
        items = parse_hunts(blobs[path] or "")
        by_file[path] = len(items)
        for it in items:
            base = f"senrigan-{kind}-{slug(it['label'])}"
            hid, k = base, 2
            while hid in seen:
                hid, k = f"{base}-{k}", k + 1
            seen.add(hid)
            if tele == "cloudtrail":
                srcs = event_sources("\n".join(it["sql"]))
            else:
                srcs = sorted(set(it["requires"]))
            tids = sorted({t.upper() for t in it["tids"]})
            attack = [t for t in tids if ATTACK_ID.fullmatch(t)]
            ttc = [t for t in tids if t not in attack and AWS_TTC_ID.fullmatch(t)]
            h = {"id": hid, "title": clean_label(it["label"]), "severity": it["severity"],
                 "attack_ids": attack, "aws_ttc_ids": ttc,
                 "telemetry": [f"{tele}/{s}" for s in srcs] or [TELEMETRY_FALLBACK[tele]],
                 "dataset": dataset, "url": blob_url("senrigan", sha, path, it["line"])}
            hunts.append(h)
    meta = {"repo": GH + "senrigan", "pinned_commit": sha, "license": "AGPL-3.0",
            "retrieved": None, "files": list(HUNT_FILES), "hunts_by_file": by_file,
            "hunts_indexed": len(hunts),
            "attribution": "AGPL-3.0: metadata and links only — no SQL, prompt or description text "
                           "is copied; open the link and run Senrigan on the consumer's own CloudTrail "
                           "or VPC Flow Logs"}
    return meta, hunts


def build(args):
    sources = {"_comment": "Per upstream repo: pinned commit, licence, retrieved date, attribution rule, "
                           "the tool that runs it on the consumer's own logs, rule counts (indexed = "
                           "Sigma documents, tagged, untagged by logsource, excluded dirs, unreadable "
                           "files), correlation files with their correlation / base document counts, "
                           "and rule_ids; for senrigan, hunts per file."}
    techniques = {}
    for repo, clone in (("hayabusa-rules", args.hayabusa_rules), ("suzaku-rules", args.suzaku_rules)):
        meta, techs = index_rules(repo, clone, args.per_technique)
        meta["retrieved"] = args.retrieved
        sources[repo] = meta
        for t, v in techs.items():
            techniques.setdefault(t, {})[repo] = v
    smeta, hunts = index_senrigan(args.senrigan)
    smeta["retrieved"] = args.retrieved
    sources["senrigan"] = smeta
    for h in hunts:   # an AWS Threat Technique Catalog id (T1562.A001) files under its ATT&CK parent
        for t in sorted(set(h["attack_ids"]) | {x.split(".")[0] for x in h["aws_ttc_ids"]}):
            techniques.setdefault(t, {}).setdefault("senrigan", []).append(h["id"])
    tech = {t: techniques[t] for t in sorted(techniques)}
    counts = {"_comment": "Totals for this build: ATT&CK techniques, rule refs listed, Sigma rule ids per "
                          "repo, correlation and base documents per repo, Senrigan hunts per file.",
              "techniques": len(tech),
              "rule_refs": sum(len(v["rules"]) for node in tech.values() for r, v in node.items()
                               if r != "senrigan"),
              "rule_ids": {r: len(sources[r]["rule_ids"]) for r in RULE_SOURCES},
              "correlation_docs": {r: sources[r]["correlation"]["correlation_docs"] for r in RULE_SOURCES},
              "base_docs": {r: sources[r]["correlation"]["base_docs"] for r in RULE_SOURCES},
              "senrigan_hunts": dict(smeta["hunts_by_file"], total=len(hunts))}
    return {
        "_comment": ("LINK-ONLY index of Yamato Security detection content, keyed by ATT&CK technique. "
                     "Per technique and rule repo: the rule count, up to per_technique_refs rule refs "
                     "(critical/high first, then by path) and, when there are more, `dirs` — every "
                     "directory holding that technique's rules with its count (link = the source's "
                     "tree_url + dir). Rule refs carry metadata only, never detection logic; `author` "
                     "is verbatim (the DRL 1.1 attribution). Every Sigma document with an id is a rule: "
                     "a correlation file's correlation rule and each of its base rules are separate "
                     "refs (kind correlation / base) with the same path and URL; a correlation inherits "
                     "no ATT&CK tag from its base rules. Rules with no ATT&CK tag are counted under "
                     "sources.<repo>.untagged by product/service/category. Every indexed rule's Sigma "
                     "id is in sources.<repo>.rule_ids, so any of them is a valid hunt_package_ref. "
                     "Senrigan hunts (AGPL-3.0: CloudTrail, Suzaku timeline and VPC Flow Log hunts) "
                     "are listed in senrigan_hunts with ids derived from their names and the telemetry "
                     "they read (cloudtrail/<eventSource>, vpcflow/<required column>); "
                     "techniques.<T>.senrigan lists the hunt ids (AWS Threat Technique Catalog "
                     "ids such as T1562.A001 file under their ATT&CK parent). The consumer runs "
                     "Hayabusa / Takajo / Suzaku / Senrigan on their own logs "
                     "(workflows/wf-threat-analyst.md Phase 5). Generated by "
                     "intel_engine/IntelAnalysis/scripts/build_yamato_index.py — do not hand-edit."),
        "retrieved": args.retrieved,
        "per_technique_refs": args.per_technique,
        "level_order": LEVELS,
        "attribution": DRL,
        "counts": counts,
        "sources": sources,
        "techniques": dict({"_comment": "ATT&CK technique -> per rule repo {count, rules (top N refs), "
                                        "dirs (only when count > N)} and senrigan (hunt ids)."}, **tech),
        "senrigan_hunts": hunts,
    }


def dump(o, ind=0):
    """JSON with one line per linked record (any object carrying `url`) and per short scalar list,
    indented one space per level otherwise — hand-readable at about half the size of indent=1."""
    pad = " " * ind
    if isinstance(o, dict) and "url" in o:
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, dict):
        if not o:
            return "{}"
        return "{\n" + ",\n".join(f"{pad} {json.dumps(k, ensure_ascii=False)}: {dump(v, ind + 1)}"
                                  for k, v in o.items()) + "\n" + pad + "}"
    if isinstance(o, list):
        if not o:
            return "[]"
        if all(not isinstance(v, (dict, list)) for v in o) and sum(len(str(v)) for v in o) < 100:
            return json.dumps(o, ensure_ascii=False)
        return "[\n" + ",\n".join(pad + " " + dump(v, ind + 1) for v in o) + "\n" + pad + "]"
    return json.dumps(o, ensure_ascii=False)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hayabusa-rules", default=os.environ.get("YS_HAYABUSA_RULES", "/tmp/ys-hayabusa-rules"))
    ap.add_argument("--suzaku-rules", default=os.environ.get("YS_SUZAKU_RULES", "/tmp/ys-suzaku-rules"))
    ap.add_argument("--senrigan", default=os.environ.get("YS_SENRIGAN", "/tmp/ys-senrigan"))
    ap.add_argument("--per-technique", type=int, default=PER_TECHNIQUE)
    ap.add_argument("--retrieved", default=RETRIEVED)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    for c in (args.hayabusa_rules, args.suzaku_rules, args.senrigan):
        if not os.path.isdir(os.path.join(c, ".git")):
            sys.exit(f"build_yamato_index: clone {c} absent")
    doc = build(args)
    body = dump(doc) + "\n"
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(body)
    s = doc["sources"]
    print(f"wrote {args.out} ({len(body.encode())} bytes): {len(doc['techniques']) - 1} techniques; "
          + "; ".join(f"{r}: {s[r]['rules_indexed']} rules, {sum(s[r]['untagged'].values())} untagged, "
                      f"{s[r]['unreadable']} unreadable, excluded {s[r]['excluded']}, "
                      f"{s[r]['correlation']['correlation_docs']} correlation + "
                      f"{s[r]['correlation']['base_docs']} base docs"
                      for r in RULE_SOURCES)
          + f"; senrigan: {s['senrigan']['hunts_by_file']}")


if __name__ == "__main__":
    main()
