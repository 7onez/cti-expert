#!/usr/bin/env python3
"""
SDK-free concurrency test for the new mcp_server dispatch architecture.

Two concurrent slow tool calls must finish in ~max time (not sum) and produce
two whole-JSON reply lines with ids {1,2}.
"""
import asyncio
import io
import json
import os
import sys
import time
import types


def check():
    """run_eval.py entry point — returns (passed, failed, lines) and exits nonzero on failure."""
    passed = failed = 0
    lines = []

    # Capture originals BEFORE any stubbing
    orig = {n: sys.modules.get(n) for n in ("tools", "audit", "mcp_server")}

    try:
        # --- Stub the heavy SDK imports inside check() ---
        fake_tools = types.ModuleType("tools")
        fake_tools.__dict__["SdkMcpTool"] = type("SdkMcpTool", (), {})
        sys.modules["tools"] = fake_tools

        fake_audit = types.ModuleType("audit")
        fake_audit.gate = lambda *a, **k: (True, "")
        sys.modules["audit"] = fake_audit

        # Import the module under test (use absolute path from __file__)
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "harness"))
        import mcp_server as ms  # noqa: E402

        # Replace the real dispatch with a slow fake
        call_times = []

        async def _fake_dispatch(method, params):
            if method == "tools/call":
                start = time.time()
                await asyncio.sleep(0.5)
                call_times.append((start, time.time()))
                return {"content": [{"type": "text", "text": "ok"}], "isError": False}
            return {}

        ms._dispatch = _fake_dispatch

        print("\n[mcp] two slow calls should finish in ~max not sum")

        msg1 = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "slow", "arguments": {}}}
        msg2 = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "slow", "arguments": {}}}

        out = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = out

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            t1 = loop.create_task(ms._handle(msg1))
            t2 = loop.create_task(ms._handle(msg2))
            loop.run_until_complete(asyncio.gather(t1, t2, return_exceptions=True))
        finally:
            sys.stdout = old_stdout
            loop.close()

        # Timing
        if len(call_times) != 2:
            raise AssertionError(f"expected 2 calls, got {len(call_times)}")
        duration = max(t[1] for t in call_times) - min(t[0] for t in call_times)
        if duration > 0.9:
            raise AssertionError(f"calls took {duration:.2f}s (should be <0.9s)")

        # Stdout: exactly two whole-JSON lines with ids {1,2}
        replies = [json.loads(line) for line in out.getvalue().strip().splitlines() if line.strip()]
        ids = {r.get("id") for r in replies if isinstance(r, dict)}
        if ids != {1, 2}:
            raise AssertionError(f"expected reply ids {{1,2}}, got {ids}")

        passed += 1
        lines.append(("ok", "mcp_server_concurrency — two slow calls finish in max not sum + whole JSON replies"))
    except Exception as e:
        failed += 1
        lines.append(("FAIL", f"mcp_server_concurrency — {e}"))
    finally:
        # Restore original modules (pop if they were absent)
        for name in ("tools", "audit", "mcp_server"):
            if orig.get(name) is not None:
                sys.modules[name] = orig[name]
            else:
                sys.modules.pop(name, None)

    return passed, failed, lines


if __name__ == "__main__":
    p, f, _ = check()
    if f:
        print(f"FAIL — {f} concurrency test(s) failed")
        raise SystemExit(1)
    print(f"PASS mcp_server_concurrency ({p} checks)")