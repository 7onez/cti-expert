#!/usr/bin/env python3
"""
cost_report.py — token usage + cost for your Claude Code sessions.

Parses Claude Code session transcripts and reports tokens and estimated cost,
broken down by model. Prices per-iteration (so Fable 5 → Opus 4.8 fallbacks are
repriced correctly) and per cache tier (5-minute vs 1-hour writes, reads).

  python3 cost_report.py                 # newest session in this project
  python3 cost_report.py --all           # every session for this project (totals)
  python3 cost_report.py --session <uuid>
  python3 cost_report.py --file <path.jsonl>
  python3 cost_report.py --by-turn       # per-turn breakdown for one session

NOTE ON ACCURACY: costs are ESTIMATES at Anthropic API *list* prices
(claude-api skill, cached 2026-06-24). If you use Claude Code on a Pro/Max
subscription, your real cost is the flat plan, not per-token — treat this as
"what these tokens would cost on the pay-as-you-go API." Refused pre-output
attempts are billed here but aren't billed by Anthropic, a tiny overestimate.
"""
import argparse
import glob
import json
import os

# --- API list prices, USD per 1M tokens (input, output). Cache derived below. ---
PRICING = {
    "claude-fable-5":    (10.0, 50.0),
    "claude-mythos-5":   (10.0, 50.0),
    "claude-opus-4-8":   (5.0,  25.0),
    "claude-opus-4-7":   (5.0,  25.0),
    "claude-opus-4-6":   (5.0,  25.0),
    "claude-opus-4-5":   (5.0,  25.0),
    "claude-sonnet-5":   (3.0,  15.0),   # intro $2/$10 through 2026-08-31
    "claude-sonnet-4-6": (3.0,  15.0),
    "claude-sonnet-4-5": (3.0,  15.0),
    "claude-haiku-4-5":  (1.0,  5.0),
}
CACHE_READ = 0.10   # × input rate
CACHE_5M   = 1.25   # × input rate (5-minute write)
CACHE_1H   = 2.00   # × input rate (1-hour write)
def _project_dir():
    """Claude Code stores session logs under ~/.claude/projects/<cwd with / and _ as ->.
    Derive it from the working directory (or $CLAUDE_PROJECT_DIR) so this is machine-portable."""
    override = os.environ.get("CLAUDE_PROJECT_DIR")
    if override:
        return os.path.expanduser(override)
    enc = os.path.abspath(os.getcwd()).replace("/", "-").replace("_", "-")
    return os.path.expanduser(f"~/.claude/projects/{enc}")


PROJECT_DIR = _project_dir()


def norm_model(m):
    if not m:
        return "unknown"
    m = m.strip()
    if m in PRICING:
        return m
    for k in PRICING:                       # tolerate date suffixes
        if m.startswith(k):
            return k
    return m


def price_usage(u, model):
    """Return (tokens_dict, cost) for one usage/iteration record at `model` rates."""
    rate = PRICING.get(model)
    inp = u.get("input_tokens", 0) or 0
    out = u.get("output_tokens", 0) or 0
    read = u.get("cache_read_input_tokens", 0) or 0
    cc = u.get("cache_creation") or {}
    w5 = cc.get("ephemeral_5m_input_tokens", 0) or 0
    w1 = cc.get("ephemeral_1h_input_tokens", 0) or 0
    if not (w5 or w1):                        # fall back to undifferentiated write count
        w5 = u.get("cache_creation_input_tokens", 0) or 0
    toks = {"input": inp, "output": out, "cache_read": read,
            "cache_write_5m": w5, "cache_write_1h": w1}
    cost = 0.0
    if rate:
        ir, orr = rate
        cost = (inp * ir + out * orr + read * ir * CACHE_READ
                + w5 * ir * CACHE_5M + w1 * ir * CACHE_1H) / 1_000_000
    return toks, cost


def account(record, agg):
    """Bill one assistant message: prefer per-iteration (correct for fallbacks)."""
    m = record.get("message") or {}
    u = m.get("usage")
    if not u:
        return 0.0
    turn_cost = 0.0
    iters = u.get("iterations")
    if iters:
        for it in iters:
            model = norm_model(it.get("model") or m.get("model"))
            toks, cost = price_usage(it, model)
            _add(agg, model, toks, cost)
            turn_cost += cost
    else:
        model = norm_model(m.get("model"))
        toks, cost = price_usage(u, model)
        _add(agg, model, toks, cost)
        turn_cost += cost
    return turn_cost


def _add(agg, model, toks, cost):
    a = agg.setdefault(model, {"cost": 0.0, "toks": {}, "priced": model in PRICING})
    a["cost"] += cost
    for k, v in toks.items():
        a["toks"][k] = a["toks"].get(k, 0) + v


def parse_file(path, agg, by_turn=False):
    turns = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                o = json.loads(line)
            except Exception:
                continue
            if (o.get("message") or {}).get("usage"):
                c = account(o, agg)
                if by_turn and c:
                    turns.append(c)
    return turns


def fmt_int(n):
    return f"{n:,}"


def report(agg, title):
    grand = sum(a["cost"] for a in agg.values())
    tot_in = sum(a["toks"].get("input", 0) for a in agg.values())
    tot_out = sum(a["toks"].get("output", 0) for a in agg.values())
    tot_read = sum(a["toks"].get("cache_read", 0) for a in agg.values())
    tot_w = sum(a["toks"].get("cache_write_5m", 0) + a["toks"].get("cache_write_1h", 0)
                for a in agg.values())
    print(f"\n=== {title} ===")
    print(f"{'model':20} {'input':>12} {'output':>10} {'cache rd':>12} "
          f"{'cache wr':>12} {'cost (USD)':>12}")
    print("-" * 82)
    for model in sorted(agg, key=lambda m: -agg[m]["cost"]):
        a = agg[model]; t = a["toks"]
        flag = "" if a["priced"] else "  (no price)"
        print(f"{model:20} {fmt_int(t.get('input',0)):>12} "
              f"{fmt_int(t.get('output',0)):>10} {fmt_int(t.get('cache_read',0)):>12} "
              f"{fmt_int(t.get('cache_write_5m',0)+t.get('cache_write_1h',0)):>12} "
              f"{'$'+format(a['cost'],'.4f'):>12}{flag}")
    print("-" * 82)
    print(f"{'TOTAL':20} {fmt_int(tot_in):>12} {fmt_int(tot_out):>10} "
          f"{fmt_int(tot_read):>12} {fmt_int(tot_w):>12} {'$'+format(grand,'.4f'):>12}")
    billed = tot_in + tot_out + tot_read + tot_w
    print(f"\nTotal tokens billed (incl. cache): {fmt_int(billed)}")
    print(f"Estimated API-list cost: ${grand:.4f}")
    print("(Estimate at pay-as-you-go API prices. On a Claude Pro/Max plan your "
          "real cost is the flat subscription, not this.)")


def main():
    ap = argparse.ArgumentParser(description="Token + cost report for Claude Code sessions.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true", help="aggregate every session in this project")
    g.add_argument("--session", help="session uuid (transcript filename without .jsonl)")
    g.add_argument("--file", help="explicit transcript .jsonl path")
    ap.add_argument("--by-turn", action="store_true", help="per-turn cost for a single session")
    ap.add_argument("--dir", default=PROJECT_DIR, help="Claude Code project transcript dir")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.dir, "*.jsonl")), key=os.path.getmtime, reverse=True)
    if not files:
        raise SystemExit(f"no transcripts in {args.dir}")

    agg = {}
    if args.all:
        for p in files:
            parse_file(p, agg)
        report(agg, f"ALL sessions ({len(files)} transcripts)")
    else:
        if args.file:
            path = args.file
        elif args.session:
            path = os.path.join(args.dir, args.session + ".jsonl")
        else:
            path = files[0]
        turns = parse_file(path, agg, by_turn=args.by_turn)
        report(agg, f"session {os.path.basename(path)}")
        if args.by_turn and turns:
            print(f"\nPer-turn cost (n={len(turns)}): "
                  f"min ${min(turns):.4f} · max ${max(turns):.4f} · "
                  f"avg ${sum(turns)/len(turns):.4f}")


if __name__ == "__main__":
    main()
