---
name: cti-proxy
description: "Manage the egress proxy / rotation pool for the skill's HTTP(S) requests (keyless crt.sh, Wayback, urlscan, CLD, WHOIS, /apikeys test; raw TLS/JARM probes need a SOCKS proxy). Add one proxy or a rotation pool, choose a policy, test, or print shell exports. Usage: /cti-proxy [status|add|remove|test|use|rotation|enable|disable]"
---

# /cti-proxy — egress proxy / rotation

Load the `cti-expert` skill, then drive the proxy layer with
`scripts/proxy/proxy.py`. Every collector routes outbound HTTP through the
process-global opener installed by `scripts/proxy/cti_proxy.py`, so configuring
it here changes the egress for the **whole skill** — keyless crt.sh, Wayback/CDX,
urlscan, the CLD connector, WHOIS, analytics-ID reverses, and `/apikeys test`.

```bash
python3 scripts/proxy/proxy.py status                       # pool + policy + toggles
python3 scripts/proxy/proxy.py add http://user:pass@host:3128 --label res-1
python3 scripts/proxy/proxy.py add 1.2.3.4:8080             # bare host:port -> http://
python3 scripts/proxy/proxy.py rotation round-robin         # | random | sticky | off
python3 scripts/proxy/proxy.py test                         # probe each proxy's egress IP
python3 scripts/proxy/proxy.py remove 0                     # drop by index or URL
python3 scripts/proxy/proxy.py disable                      # back to your real IP
```

## How it behaves

- **Pool + failover.** Add several proxies; a dead one is skipped to the next.
  An origin HTTP error (4xx/5xx) is *not* retried — the proxy worked, the server
  answered.
- **Rotation.** `round-robin` advances one proxy per script invocation (persisted
  on disk) so successive collections egress from different IPs. `random` picks per
  run; `sticky`/`off` pin the first.
- **No-leak default.** With a pool set, a direct connection is **never** used as a
  fallback unless you run `allow-direct on` — the point of a proxy is to not expose
  the real IP on a hostile case.
- **Precedence.** Env `CTI_PROXY` / `CTI_PROXIES` (and standard `HTTPS_PROXY`)
  override the stored pool — use them for a one-off session without editing the store.
- **Accepted input formats.** `add` takes any of: a full URL
  `scheme://[user:pass@]host:port`; a bare `host:port`; a provider export
  `host:port:user:pass`; a `user:pass@host:port` authority; even a pasted
  `http_proxy="http://…"` assignment (prefix + quotes are stripped). Credentials
  are always masked in output but stored intact for the opener.
- **SOCKS.** `socks5://` / `socks5h://` are supported; `add` **auto-installs
  PySocks** on demand. Caveat: a SOCKS pool rotates **per run** but has **no
  in-process failover**, and `no_proxy` is **not** enforced (PySocks hooks the
  global socket, routing everything). HTTP/HTTPS pools get the full failover +
  `no_proxy` behavior above. PySocks must be present in the **interpreter that runs
  the tool** — `add` installs it for the current one, but the `intel.py` pipeline
  runs tools under `$INTEL_PY`; where it's absent the hook can't install and raw
  probes **fail closed** (no leak) rather than dialling direct, so install it there.

## Coverage

- **Broad collectors** (`scripts/…` — `/webpivot`, `/subdomain`, Wayback, `/cld`,
  WHOIS, `/apikeys test`, …) get **full in-process rotation + failover**: they
  bootstrap the process-global opener at startup.
- **The deep pipeline** (`/backend`, `/pipeline`, `/harness` via
  `scripts/backend/intel.py`) spawns its tools with the inherited environment, so
  every intel_engine tool **honors the same egress** (one proxy per pipeline run;
  rotation advances per run). Full per-request failover is a collector feature.
- **Ad-hoc tool calls / the MCP server:** export first with
  `eval "$(python3 scripts/proxy/proxy.py use)"`, then run the tool.
- **Raw-socket TLS probes.** The cert-SHA probes (`wp_pssl.py`, `wp_recon.py`),
  `/cert-pivot`'s leaf probe, and JARM (`jarm.py`) all take their socket from
  `cti_proxy.proxied_connection`: **CONNECT-tunnelled and fail closed** under an
  HTTP pool (never a direct dial), carried by the in-process socket hook under a
  SOCKS pool, direct only with no proxy. As a policy choice the `/webpivot` analyze
  path additionally **skips JARM under an HTTP pool** (ten tunnelled handshakes are
  slow) and runs it under SOCKS / no proxy — honoring the env/pool proxy, not just
  an explicit `--proxy`.

## Notes

1. **Store is secret.** `scripts/proxy/proxies.json` may hold proxy credentials —
   it is gitignored and written chmod-600. Never commit it.
2. **Shell / other tools.** `python3 scripts/proxy/proxy.py use` prints
   `export HTTP(S)_PROXY=…` lines (advancing rotation) to `eval` in a shell so any
   external CLI inherits the same egress.
3. **Verify egress.** Run `test` — it reports the public IP each proxy exits from,
   confirming the route before you collect against a live target.
