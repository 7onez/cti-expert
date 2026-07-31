---
name: cti-status
description: "Health check — backend tier, case store, MCP tools, API credit balances. Run this when something behaves oddly. Usage: /cti-status"
---

# /cti-status — health check

Load the `cti-expert` skill, then report the runtime state.

```bash
python3 scripts/backend/backend.py status      # tier + $INTEL_HOME resolution
python3 scripts/backend/intel.py list          # every dispatchable op
python3 scripts/backend/intel.py cases         # what is in the case store
python3 scripts/backend/intel.py api-usage     # metered credits spent
```

Expected: `Tier 2 (CLI) — $INTEL_HOME=<repo>/intel_engine (via in-repo (self-contained))`.

Check in order:

1. **Backend resolves?** If not, `$INTEL_HOME` is wrong or the vendored engine is missing.
2. **MCP server live?** `/mcp` should list the `intel` server. If it is absent, generate the
   registration with `python3 scripts/backend/intel.py mcp --write` — `.mcp.json` is git-ignored
   and per-machine by design.
3. **One case store?** Everything lives in `$INTEL_HOME/cases/`. A `cases/` directory at the repo
   root is always a mistake and makes ingestion silently find nothing.
4. **Credits?** WhoisXML bills Whois History and Reverse WHOIS to the **Domain Research Suite**
   balance, not the WHOIS API balance. Zero DRS returns 200 for current WHOIS and 403 for both of
   those — a valid key that looks broken.
