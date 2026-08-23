#!/usr/bin/env python3
"""
en_engage.py — the GATED half of Engage: create an account on the target, log in, and capture the
members area as evidence. Outbound, attributable, irreversible — so it is treated like BinaryPivot's
ANY.RUN submission, not like a page read.

THE GATE (same shape as bp_anyrun.submit)
------------------------------------------
`engage()` REFUSES unless `confirm=True` is passed to the function, and returns `preflight()` — the
risk briefing plus the cheaper things to try first — instead. `confirm` and `synthetic_identity_only`
are enforced in the SIGNATURE, not read from the JSON, so a stale or edited `engagement_policy` can
only make the gate STRICTER, never turn it off. The harness adds a second lock: `engage_submit` is in
the audit gate's approval_required list (env `INTEL_ENGAGE_CONFIRM=1`), so an agent loop cannot reach
the first gate on its own.

WHAT IT WILL NOT DO
-------------------
  * It never solves or evades a CAPTCHA and never bypasses an OTP/2FA step. If en_forms reported a
    blocker, engagement stops at it and hands back to the human — a UA swap is not a challenge bypass.
  * It never uses real PII. The persona must come from en_persona.py (kind == synthetic-*).
  * It warns hard and refuses DIRECT egress unless `allow_direct_egress=True` — a signup from the
    analyst's own IP is a self-identifying beacon. Pass `--proxy` (a research VPS/VPN) normally.

EXECUTION
---------
Registration + login are driven with Playwright (a real browser — a raw POST trips anti-bot and
misses JS validation). Playwright is an OPTIONAL dependency; without it, `engage()` returns a manual
runbook (the fields to fill from the persona, the actions, what to capture) so the analyst can do it
by hand. Every step is screenshotted and the authenticated DOM saved under cases/<case>/engage/, and
one line per engagement is appended to cases/<case>/engage/interactions.jsonl (an audit + evidence
record). What the account reveals is treated as sensitive case material (see engagement_policy.data_handling).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from en_refs import load_ref, ref_path  # noqa: E402

_FALLBACK_POLICY = {
    "require_explicit_confirmation": True, "synthetic_identity_only": True,
    "require_nonattributable_egress": True, "never_auto_solve_captcha": True,
    "never_reuse_real_pii": True,
    "risks": ["Engagement is outbound, attributable and irreversible."],
    "try_first": ["Run en_forms.py first; look for existing/leaked credentials before minting an account."],
    "data_handling": ["Persona + captures are case evidence; never reuse a persona across cases."],
}
_REF = load_ref(ref_path(__file__, "engage.json"),
                {"engagement_policy": _FALLBACK_POLICY,
                 "modal_dismiss_labels": ["Close", "Đóng", "Bỏ qua", "Skip", "Nhắc lại sau",
                                          "Đã hiểu", "OK", "Dismiss", "×"]})
POLICY = _REF.get("engagement_policy", _FALLBACK_POLICY)
MODAL_DISMISS = _REF.get("modal_dismiss_labels") or []


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def preflight(url: str, persona: dict = None, proxy: str = None) -> dict:
    """The briefing an analyst must see BEFORE an engagement — never a skippable step.

    Returned by `engage()` whenever confirmation is absent. Meant to be shown verbatim and put to
    the human as a yes/no; consent to 'investigate this site' is NOT consent to create an account
    on the operator's own box."""
    return {
        "action": "CONFIRMATION REQUIRED — nothing has been sent; no account created",
        "target": url,
        "irreversible": True,
        "why_it_is_gated": (
            "Creating an account is an outbound POST to the operator's backend. They see a new "
            "member at a known time from your egress, with a browser fingerprint, and can tie it "
            "to the report later. You cannot un-register."),
        "risks": list(POLICY.get("risks") or []),
        "try_first": list(POLICY.get("try_first") or []),
        "egress": ("via proxy: " + proxy) if proxy else (
            "DIRECT — this would originate from the analyst's own network. Strongly discouraged; "
            "pass --proxy <research VPS/VPN>, or override with --allow-direct-egress if you accept it."),
        "identity": (_persona_line(persona) if persona else
                     "no persona supplied — mint one with en_persona.py (synthetic, one per case)"),
        "will_not": [
            "solve or evade a CAPTCHA", "bypass an OTP / 2FA step", "use real PII",
            "reuse a persona across cases",
        ],
        "data_handling": list(POLICY.get("data_handling") or []),
        "to_proceed": ("ask the analyst explicitly, then call engage(..., confirm=True) — or "
                       "`en_engage.py <url> --persona p.json --confirm-engagement` on the CLI "
                       "(the harness also requires INTEL_ENGAGE_CONFIRM=1)"),
    }


def _persona_line(p):
    if not isinstance(p, dict):
        return "invalid persona"
    return (f"{p.get('username')} <{p.get('email')}> "
            f"[{p.get('kind', 'UNKNOWN — refuse if not synthetic')}]")


def _is_synthetic(persona: dict) -> bool:
    return isinstance(persona, dict) and str(persona.get("kind", "")).startswith("synthetic")


def _plan_from_detection(detection: dict, persona: dict) -> dict:
    """Map the detected register form's fields to persona values — the fill plan (also the manual
    runbook when Playwright is absent). Never invents a value it does not have."""
    surface = (detection or {}).get("auth_surface", {})
    regs = surface.get("register") or []
    if not regs:
        return {"error": "no registration form in the supplied detection result — run en_forms first"}
    form = max(regs, key=lambda r: r.get("confidence", 0))
    # heuristics mapping a field name to a persona key
    def val_for(f):
        hay = (f.get("name", "") + f.get("id", "") + f.get("placeholder", "")).lower()
        for key, toks in (("email", ("email", "e-mail")), ("username", ("user", "login", "account", "nick")),
                          ("password", ("confirm", "repeat", "retype")), ("password", ("pass", "pwd")),
                          ("phone", ("phone", "tel", "mobile")), ("full_name", ("name",)),
                          ("dob", ("birth", "dob")), ("country", ("country",)), ("city", ("city",)),
                          ("address", ("address", "street")), ("postal", ("zip", "postal"))):
            if any(t in hay for t in toks):
                return persona.get(key, "")
        return ""
    fills = []
    for f in form.get("fields", []):
        if f.get("type") in ("checkbox",):
            fills.append({"field": f.get("name") or f.get("id"), "action": "check (terms)"})
        else:
            v = val_for(f)
            fills.append({"field": f.get("name") or f.get("id"), "type": f.get("type"),
                          "value": v or "(NO PERSONA VALUE — supply or leave blank)"})
    return {"form_action": form.get("action"), "method": form.get("method"),
            "fills": fills, "submit_labels": form.get("submit_labels", []),
            "blockers": (detection.get("engagement_plan", {}) or {}).get("blockers", [])}


def _record(case: str, url: str, event: dict):
    if not case:
        return None
    root = os.environ.get("INTEL_ROOT") or os.getcwd()
    d = os.path.join(root, "cases", case, "engage")
    os.makedirs(d, exist_ok=True)
    line = dict(event, ts=_utcnow(), url=url)
    with open(os.path.join(d, "interactions.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, ensure_ascii=False) + "\n")
    return os.path.join(d, "interactions.jsonl")


def engage(url: str, persona: dict, detection: dict = None, *, confirm: bool = False,
           proxy: str = None, allow_direct_egress: bool = False, case: str = None,
           do_login: bool = True, await_confirm: bool = False, target_domain: str = None) -> dict:
    """Register (and optionally log in) with the SYNTHETIC persona. Refuses unless confirm=True.

    Returns preflight() when unconfirmed. When confirmed: refuses a non-synthetic persona; refuses
    direct egress unless allowed; stops at any CAPTCHA/OTP blocker; drives Playwright if present,
    else returns a manual runbook. Records every step under the case."""
    if not confirm:
        return preflight(url, persona, proxy)
    if POLICY.get("synthetic_identity_only", True) and not _is_synthetic(persona):
        return {"refused": ("persona is not a synthetic research identity (kind must start with "
                            "'synthetic') — engagement never uses real PII. Mint one with en_persona.py."),
                "preflight": preflight(url, persona, proxy)}
    if POLICY.get("require_nonattributable_egress", True) and not proxy and not allow_direct_egress:
        return {"refused": ("no research egress set. A signup from your own IP is a self-identifying "
                            "beacon. Pass proxy=<research VPS/VPN>, or allow_direct_egress=True to "
                            "accept direct egress knowingly."),
                "preflight": preflight(url, persona, proxy)}

    plan = _plan_from_detection(detection, persona) if detection else None
    blockers = (plan or {}).get("blockers") or (
        (detection or {}).get("engagement_plan", {}) or {}).get("blockers", [])
    if any(b.startswith("captcha") for b in blockers):
        _record(case, url, {"event": "blocked", "reason": "captcha", "blockers": blockers})
        return {"blocked": "CAPTCHA present — the tool never solves or evades it. A human decides.",
                "blockers": blockers, "plan": plan}
    # A verification step is only a hard block if we CAN'T satisfy it. Email confirmation with a
    # real puppet inbox is handled below (await_confirm); SMS/authenticator OTP still stops here.
    sms_otp = any(("sms" in b or "2fa" in b or "authenticator" in b) for b in blockers)
    email_verify = any(("otp" in b or "verification" in b) for b in blockers) and not sms_otp
    persona_has_real_inbox = bool(persona.get("email")) and not str(persona["email"]).endswith(".invalid")
    if sms_otp or (email_verify and not (await_confirm and persona_has_real_inbox)):
        _record(case, url, {"event": "blocked", "reason": "verification", "blockers": blockers})
        return {"blocked": ("verification step present — for email confirmation, mint a persona on a "
                            "puppet inbox (en_persona --from-pool) and pass await_confirm=true so "
                            "en_inbox fetches the link; SMS/authenticator OTP the tool never bypasses."),
                "blockers": blockers, "plan": plan}

    # try Playwright; fall back to a manual runbook
    try:
        import playwright  # noqa: F401
        have_pw = True
    except ImportError:
        have_pw = False

    if not have_pw:
        _record(case, url, {"event": "manual_runbook", "persona": persona.get("username")})
        return {
            "mode": "manual-runbook",
            "note": ("Playwright not installed — returning a fill-by-hand runbook instead of "
                     "driving the browser. `pip install playwright && playwright install chromium` "
                     "to automate. Do the signup from research egress; capture the members area."),
            "egress": proxy or "DIRECT (accepted)",
            "plan": plan,
            "steps": [
                "1. Register with the persona values above (from research egress).",
                ("2. If email confirmation is required, open the puppet inbox for "
                 f"{persona.get('email')} and click the confirm link — or run "
                 "`en_inbox.py wait <address> --target-domain <domain>` to fetch it."),
                "3. Log in with the identifier + password.",
                "4. Save the authenticated DOM and run en_harvest.py on it.",
            ],
            "mission": ["crypto wallet addresses (deposit page)", "bank / payee account details",
                        "the service flow (deposit→task/trade→withdraw-block→top-up)",
                        "the credential-harvester upload path"],
        }

    return _drive_playwright(url, persona, plan, detection, proxy, case, do_login,
                             await_confirm, target_domain)


def _login(page, detection, persona):
    """Fill and submit the detected login form with the persona's identifier + password."""
    surface = (detection or {}).get("auth_surface", {})
    logins = surface.get("login") or []
    if not logins:
        return False
    form = max(logins, key=lambda r: r.get("confidence", 0))
    ident = persona.get("email") or persona.get("username")
    for f in form.get("fields", []):
        hay = (f.get("name", "") + f.get("id", "") + f.get("placeholder", "")).lower()
        try:
            sel = f"[name='{f.get('name')}']" if f.get("name") else f"#{f.get('id')}"
            if f.get("type") == "password" or "pass" in hay:
                page.fill(sel, persona.get("password", ""), timeout=4000)
            elif any(t in hay for t in ("email", "user", "login", "account", "phone")) or f.get("type") in ("email", "tel"):
                page.fill(sel, ident, timeout=4000)
        except Exception:
            pass
    try:
        page.click("button[type=submit], input[type=submit]", timeout=5000)
        page.wait_for_load_state("networkidle", timeout=15000)
        return True
    except Exception:
        return False


def _dismiss_dialogs(page):
    """Click the first close/skip/later/understood control inside the top-most modal, so an
    interstitial overlay (cookie notice, 'link Telegram' nag, payment splash) stops intercepting
    clicks on the form/panel beneath it. Never touches a submit/confirm control, never a CAPTCHA.
    Returns the label it clicked, or None. Observed necessary on a live VN fraud panel where both
    registration and the deposit walk stalled on an aria-modal overlay."""
    try:
        import json as _json
        labels = _json.dumps(MODAL_DISMISS)
        return page.evaluate(
            "(labels)=>{const L=JSON.parse(labels);"
            "const ds=[...document.querySelectorAll('[role=dialog],[aria-modal=\"true\"]')];"
            "const d=ds[ds.length-1]; if(!d) return null;"
            "const btns=[...d.querySelectorAll('button,a,[role=button]')];"
            "for(const t of L){const b=btns.find(e=>((e.innerText||e.getAttribute('aria-label')||'').trim()===t));"
            "if(b){b.click();return t;}}"
            "return null;}", labels)
    except Exception:
        return None


def _drive_playwright(url, persona, plan, detection, proxy, case, do_login,
                      await_confirm=False, target_domain=None):
    """Register + login in a real browser, screenshotting each step. Best-effort field filling from
    the plan; never auto-solves anything. Captures API responses (SPA money lives in XHR, not the
    DOM) and dismisses interstitial modals. Returns what it captured + evidence paths."""
    from playwright.sync_api import sync_playwright
    root = os.environ.get("INTEL_ROOT") or os.getcwd()
    ev = os.path.join(root, "cases", case or "_scratch", "engage",
                      "session_" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    os.makedirs(ev, exist_ok=True)
    shots, captured = [], {}
    launch = {"headless": True}
    if proxy:
        launch["proxy"] = {"server": proxy}
    api_bodies = []

    def _on_resp(r):
        u = r.url.split("?")[0]
        if "/api/" in u and "_next" not in u:
            try:
                if "json" in (r.headers.get("content-type") or ""):
                    api_bodies.append({"m": r.request.method, "s": r.status, "u": u, "b": r.text()[:4000]})
            except Exception:
                pass

    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch)
        page = browser.new_context().new_page()
        page.on("response", _on_resp)
        try:
            reg_url = (plan or {}).get("form_action") or url
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(1200)
            _dismiss_dialogs(page)  # clear any interstitial overlay before touching the form
            shots.append(_shot(page, ev, "01_landing"))
            # fill the registration form best-effort by field name
            for fill in (plan or {}).get("fills", []):
                fld, v = fill.get("field"), fill.get("value")
                if not fld:
                    continue
                try:
                    if fill.get("action", "").startswith("check"):
                        page.check(f"[name='{fld}']", timeout=3000)
                    elif v and not v.startswith("("):
                        page.fill(f"[name='{fld}']", v, timeout=3000)
                except Exception:
                    pass  # a field we couldn't locate is logged by absence, not fabricated
            shots.append(_shot(page, ev, "02_filled"))
            _record(case, url, {"event": "register_attempt", "persona": persona.get("username"),
                                "action": reg_url})
            # NOTE: the actual submit click is left to a labelled selector so the analyst can see
            # exactly what was filled first; auto-submit only when a clear submit control exists.
            try:
                page.click("button[type=submit], input[type=submit]", timeout=5000)
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            page.wait_for_timeout(1000)
            _dismiss_dialogs(page)  # a post-signup 'link Telegram'/notice modal blocks the panel
            shots.append(_shot(page, ev, "03_after_register"))

            # KYC / email confirmation — fetch the link from the puppet inbox and click it here,
            # so the click originates from the research egress (never from en_inbox).
            if await_confirm and persona.get("email") and not str(persona["email"]).endswith(".invalid"):
                try:
                    import en_inbox
                    conf = en_inbox.wait_confirm(persona["email"], target_domain or _dom(url))
                    captured["confirmation"] = {k: conf.get(k) for k in
                                                ("confirmed_email_found", "confirm_link", "subject")}
                    if conf.get("confirm_link"):
                        page.goto(conf["confirm_link"], wait_until="domcontentloaded", timeout=30000)
                        shots.append(_shot(page, ev, "04_after_confirm"))
                        _record(case, url, {"event": "email_confirmed", "subject": conf.get("subject")})
                except Exception as exc:  # noqa: BLE001
                    captured["confirmation_error"] = str(exc)

            # log in, then capture the AUTHENTICATED members area
            if do_login:
                if _login(page, detection, persona):
                    shots.append(_shot(page, ev, "05_after_login"))
                    _record(case, url, {"event": "login_attempt", "persona": persona.get("username")})

            dom_path = os.path.join(ev, "authenticated_dom.html")
            content = page.content()
            with open(dom_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            captured["authenticated_dom"] = dom_path
            captured["final_url"] = page.url
        finally:
            browser.close()

    # persist the captured API responses — on an API-driven SPA this is where the money is
    if api_bodies:
        with open(os.path.join(ev, "api_log.json"), "w", encoding="utf-8") as fh:
            json.dump(api_bodies, fh, ensure_ascii=False, indent=1)
        captured["api_log"] = os.path.join(ev, "api_log.json")

    # run the MISSION harvest over BOTH the DOM and the captured API responses
    mission = None
    try:
        import en_harvest
        mission = en_harvest.harvest(content, base_url=captured.get("final_url", url))
        if api_bodies:
            mission["api_mission"] = en_harvest.harvest_api([x["b"] for x in api_bodies])
        _record(case, url, {"event": "harvest",
                            "found": {"dom_wallets": len(mission.get("wallets", [])),
                                      "api_wallets": len(mission.get("api_mission", {}).get("wallets", [])),
                                      "api_banks": len(mission.get("api_mission", {}).get("bank_details", []))}})
    except Exception as exc:  # noqa: BLE001
        mission = {"error": f"harvest failed: {exc}"}

    _record(case, url, {"event": "session_captured", "evidence_dir": ev, "shots": len([s for s in shots if s])})
    return {
        "mode": "playwright",
        "note": ("Registered + attempted login with the synthetic persona, then harvested the "
                 "members area. Verify the account state by eye — a fresh no-deposit view may be a "
                 "decoy, and a thin panel is not proof the operation is thin."),
        "egress": proxy or "DIRECT (accepted)",
        "evidence_dir": ev, "screenshots": [s for s in shots if s], "captured": captured,
        "mission": mission,
        "next": ("feed the mission pivots — deposit wallets, bank/payee accounts, the credential-"
                 "harvester upload path, backend/API hosts, referral tree, support handles — back "
                 "into WebPivot + IntelAnalysis, where each is base-rate checked before it attributes."),
    }


def _dom(url):
    from urllib.parse import urlparse
    return (urlparse(url).netloc or "").split(":")[0]


def _shot(page, ev, name):
    p = os.path.join(ev, name + ".png")
    try:
        page.screenshot(path=p, full_page=True)
    except Exception:
        return None
    return p


def main(argv=None):
    ap = argparse.ArgumentParser(description="GATED: create an account + log in to gather intel.")
    ap.add_argument("url", help="the registration/login URL")
    ap.add_argument("--persona", help="path to a synthetic persona JSON (en_persona.py)")
    ap.add_argument("--detection", help="path to an en_forms.py result JSON (the fill plan)")
    ap.add_argument("--proxy", help="research egress (VPS/VPN) — strongly recommended")
    ap.add_argument("--allow-direct-egress", action="store_true",
                    help="proceed from your own IP (self-identifying — only if you accept it)")
    ap.add_argument("--case", help="cases/<case>/engage/ for evidence + audit")
    ap.add_argument("--await-confirm", action="store_true",
                    help="email-gated signup: fetch the confirm link from the persona's puppet "
                         "inbox (en_inbox) and click it before login")
    ap.add_argument("--target-domain", help="domain to match the confirmation email against")
    ap.add_argument("--no-login", action="store_true", help="register only, do not log in")
    ap.add_argument("--confirm-engagement", action="store_true",
                    help="REQUIRED to actually act; without it you get the preflight briefing")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args(argv)

    persona = json.load(open(args.persona, encoding="utf-8")) if args.persona else None
    detection = json.load(open(args.detection, encoding="utf-8")) if args.detection else None

    # second lock, mirroring the harness audit gate, so the CLI alone can't act unattended
    env_ok = os.environ.get("INTEL_ENGAGE_CONFIRM") == "1"
    confirm = args.confirm_engagement and env_ok
    if args.confirm_engagement and not env_ok:
        print("[en_engage] --confirm-engagement given but INTEL_ENGAGE_CONFIRM=1 is not set; "
              "showing preflight instead of acting.", file=sys.stderr)

    result = engage(args.url, persona or {}, detection, confirm=confirm, proxy=args.proxy,
                    allow_direct_egress=args.allow_direct_egress, case=args.case,
                    do_login=not args.no_login, await_confirm=args.await_confirm,
                    target_domain=args.target_domain)
    print(json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
