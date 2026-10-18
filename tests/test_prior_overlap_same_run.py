#!/usr/bin/env python3
"""Regression: `_prior_overlap` must not report THIS run's own reverse-WHOIS/subenum siblings as
prior knowledge (#6).

WHAT THIS PROTECTS
------------------
`cmd_open` ingests the seed's raw JSON — which, with `--whois-reverse`, ALSO turns up other domains
sharing the seed's registrant as KB edges in the very same ingest — then immediately calls
`_prior_overlap(hosts)`. Before this fix, `_prior_overlap` read the KB's edges with no notion of
WHEN each peer domain first appeared, so a domain that had existed in the KB for years (genuine
prior-case knowledge) and a domain the ingest a few lines above had just created were reported
identically as "prior domain(s) share an indicator with this case's seeds" — implying a
pre-existing link to the analyst that never existed for the just-created one. This builds a
synthetic KB with one OLD peer (2020) and one peer created AT this run's start, and asserts the OLD
peer is reported as prior while the NEW one is called out separately as "discovered THIS RUN".
"""
import contextlib
import datetime
import importlib.util
import io
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
KB_TOOLS_DIR = os.path.join(ENGINE, "tools", "kb")
sys.path.insert(0, KB_TOOLS_DIR)
from knowledge_base import KB as _KBClass  # noqa: E402


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    IP = _load_module(os.path.join(ENGINE, "tools", "intel.py"), "cti_intel_pipeline_under_test")

    with tempfile.TemporaryDirectory() as tmp:
        kbdir = os.path.join(tmp, "knowledge")
        kb = _KBClass(kbdir)

        old_ts = "2020-01-01T00:00:00+00:00"
        now = datetime.datetime.now(datetime.timezone.utc)
        now_ts = now.isoformat(timespec="seconds")
        since_ts = now.timestamp() - 1   # "this run" started 1s before the fresh sibling appeared

        # the seed itself (excluded from peer reporting regardless of timestamp)
        kb.add_edge("domain", "seed.example", "registered_by", "email", "shared@example.com",
                    "whoisxml", "webpivot/whois_enrich", now_ts, "high")
        # a domain that has shared this registrant since long before this run — genuine prior case
        kb.add_edge("domain", "prior-sibling.example", "registered_by", "email",
                    "shared@example.com", "whoisxml", "webpivot/whois_enrich", old_ts, "high")
        # a domain that appears in the KB for the FIRST time as part of this same ingest (e.g. a
        # --whois-reverse sibling discovered from the seed's own raw file)
        kb.add_edge("domain", "fresh-sibling.example", "registered_by", "email",
                    "shared@example.com", "whoisxml", "webpivot/whois_enrich", now_ts, "high")

        IP.KB = kbdir   # point the module's data-dir constant at the synthetic KB

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            IP._prior_overlap(["seed.example"], since_ts=since_ts)
        out = buf.getvalue()

        ok("prior-sibling.example" in out, "the genuinely-old peer is reported")
        ok("discovered THIS RUN" in out, "a this-run discovery gets its own labelled line")
        ok("fresh-sibling.example" in out, "the this-run peer is named (in the discovered-this-run line)")
        # the fresh peer must NOT appear in the "prior domain(s)" list itself
        prior_section = out.split("discovered THIS RUN")[-1] if "discovered THIS RUN" in out else out
        ok("fresh-sibling.example" not in out.split("prior domain(s) share")[-1].split("\n")[1]
           if "prior domain(s) share" in out else True,
           "the this-run peer is not ALSO listed as a prior domain")

        # without since_ts (old call signature / behaviour) both are treated as prior — this proves
        # the fix is the since_ts split, not a change to what counts as a "peer" at all
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            IP._prior_overlap(["seed.example"])
        out2 = buf2.getvalue()
        ok("fresh-sibling.example" in out2 and "prior-sibling.example" in out2 and
           "discovered THIS RUN" not in out2,
           "omitting since_ts falls back to the old (pre-#6) behaviour — proves since_ts is what changed")

    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"{_status:>4}  {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
