#!/usr/bin/env python3
"""
test_engage.py — the gate on the Engage skill (auth-surface detection + the gated engagement).

Run:  python3 tests/test_engage.py
      python3 tools/eval/run_eval.py         (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
Two things, with different failure modes:

  1. DETECTION must classify by FIELDS, not URL words — a confirm-password field is a registration
     tell, an identifier+password is a login, and an invite code is a pivot, not an OTP. A drift
     here silently mislabels the auth surface and sends the analyst at the wrong form.
  2. The ENGAGEMENT GATE must hold. engage() must refuse without confirm, refuse a non-synthetic
     persona, refuse direct egress, and STOP at a CAPTCHA — each enforced in code, not just prose,
     so a stale engage.json cannot loosen it. A regression here would let an agent create an account
     on hostile infrastructure unattended, which is the whole thing this skill is built NOT to do.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "Engage", "tools"))

LOGIN_HTML = """<form id="login" method="post" action="/api/v1/auth/login">
  <input type="email" name="email"><input type="password" name="password">
  <button type="submit">Sign In</button></form><a href="/register">Create an account</a>"""

REGISTER_HTML = """<form method="post" action="https://api.backend.example/signup">
  <input type="text" name="username"><input type="email" name="email">
  <input type="password" name="password"><input type="password" name="confirm_password">
  <input type="text" name="invite_code"><input type="checkbox" name="agree_terms">
  <div class="g-recaptcha" data-sitekey="x"></div><button type="submit">Register</button></form>"""

RESET_HTML = """<form action="/forgot"><input type="email" name="email">
  <button>Recover password</button></form>"""

PANEL_HTML = """<h2>Deposit USDT TRC20</h2><p>Address: TExampLeTronAddressDoNotUseXXXXXXX</p>
  <p>ETH: 0x52908400098527886E0F7030069857D2E4169EE7</p>
  <h3>Bank</h3><p>IBAN: DE89370400440532013000 SWIFT: DEUTDEFF beneficiary payee</p>
  <div>VIP task commission withdraw</div>
  <form action="/api/upload/kyc" method="post"><input type="file" name="id_card">
  <input name="card_number"><input name="cvv"><button>Upload</button></form>"""


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    import en_forms
    import en_persona
    import en_engage
    import en_harvest

    # --- 1. reference file actually loaded (not the embedded fallback) -----------------------
    ok(len(en_forms.REGISTER_TERMS) > len(en_forms._FALLBACK["register_submit_terms"]),
       "en_forms loaded engage.json (register terms richer than fallback)")
    ok("engagement_policy" in en_engage.POLICY or en_engage.POLICY.get("require_explicit_confirmation"),
       "en_engage loaded the engagement_policy")

    # --- 2. DETECTION classifies by fields --------------------------------------------------
    login = en_forms.detect(LOGIN_HTML, "https://site.example")
    ok(len(login["forms"]["login"]) == 1, "login form detected")
    ok(login["forms"]["login"][0]["action"].endswith("/api/v1/auth/login"),
       "login auth_endpoint captured (absolute)")
    ok("/register" in " ".join(login["register_links"]) or any(
        "/register" in x for x in login["register_links"]), "register link found for the one-hop crawl")

    reg = en_forms.detect(REGISTER_HTML, "https://site.example")
    ok(len(reg["forms"]["register"]) == 1 and not reg["forms"]["login"],
       "confirm-password form classified as REGISTER, not login")
    sig = reg["forms"]["register"][0]["signals"]
    ok("confirm_password_field" in sig, "confirm-password tell recorded")
    ok("referral_field" in sig, "invite/referral field recorded")
    ok("otp_field" not in sig, "invite_code NOT misread as an OTP field")
    ok(reg["captcha"], "captcha marker detected")

    reset = en_forms.detect(RESET_HTML, "https://site.example")
    ok(len(reset["forms"]["password_reset"]) == 1, "password-reset (identifier, no password) classified")

    spa = en_forms.detect("<div id='app'></div><a href='/login'>Login</a>", "https://site.example")
    note = en_forms._plan_note(spa["forms"]["login"], spa["forms"]["register"], [], True, spa)
    ok("static HTML" in note, "SPA with no static form reports 'render it', not 'no login'")

    # Real BillHD shape: a React panel whose only auth signal is the words "Đăng nhập"/"đăng ký"
    # in the nav — no <form>, no auth <a href>. Must escalate to 'render the auth route', not
    # 'no login'. (regression for the case-billhd run)
    react_nav = "<div id='main'></div><script>ReactDOM.render()</script><nav>Đăng nhập · đăng ký</nav>"
    ok(en_forms._looks_spa(react_nav), "React build detected as SPA even without id=root")
    ok(en_forms._auth_words_in_text(react_nav), "VN login/register wording detected in page text")
    rnote = en_forms._plan_note([], [], [], en_forms._looks_spa(react_nav), spa,
                                en_forms._auth_words_in_text(react_nav))
    ok("CLIENT-SIDE ROUTE" in rnote and "no login" not in rnote.lower(),
       "auth-words-without-a-form escalates to 'render the auth route', not 'no login'")

    # full analyze() on the register page → engagement plan blockers
    full = en_forms._finish("register.html", "https://site.example", 200,
                            reg, {"login": [], "register": reg["forms"]["register"],
                                  "password_reset": []}, reg["captcha"], [], spa=False, proxy=None)
    ok(not full["engagement_plan"]["registerable"], "registerable=false when a CAPTCHA blocks signup")
    ok(any(p["kind"] == "referral_field" for p in full["pivots"]), "referral pivot emitted")

    # --- 3. PERSONA is synthetic, carries no real PII ---------------------------------------
    p = en_persona.generate()
    ok(p["kind"].startswith("synthetic"), "persona kind is synthetic")
    ok(p["email"].endswith(".invalid"), "persona email is a non-deliverable placeholder by default")
    ok(len(p["password"]) >= 12, "persona password is strong")
    ok("phone" not in p, "no phone unless requested")
    p2 = en_persona.generate(email_domain="inbox.example", with_phone=True)
    ok(p2["email"].endswith("@inbox.example") and "phone" in p2, "email domain + placeholder phone honoured")

    # --- 4. THE ENGAGEMENT GATE (each enforced in code) -------------------------------------
    pre = en_engage.engage("https://s.example", p, None, confirm=False)
    ok(str(pre.get("action", "")).startswith("CONFIRMATION REQUIRED"), "no confirm -> preflight, nothing sent")

    real_persona = {"kind": "real", "username": "x", "email": "x@x.com", "password": "p"}
    r = en_engage.engage("https://s.example", real_persona, None, confirm=True, proxy="http://p")
    ok("refused" in r and "synthetic" in r["refused"], "non-synthetic persona refused")

    r = en_engage.engage("https://s.example", p, None, confirm=True)  # no proxy, no override
    ok("refused" in r and "egress" in r["refused"].lower(), "direct egress refused")

    det = {"engagement_plan": {"blockers": ["captcha:recaptcha"]},
           "auth_surface": {"register": [{"confidence": 0.9, "action": "/s", "fields": []}]}}
    r = en_engage.engage("https://s.example", p, det, confirm=True, proxy="http://p")
    ok("blocked" in r and "CAPTCHA" in r["blocked"], "engagement STOPS at a CAPTCHA")

    ok(en_engage.POLICY.get("require_explicit_confirmation") is True
       and en_engage._is_synthetic(p) and not en_engage._is_synthetic(real_persona),
       "synthetic check + policy flags present")

    # --- 5. HARVEST the mission -------------------------------------------------------------
    h = en_harvest.harvest(PANEL_HTML, base_url="https://site.example")
    wallets = {w["value"] for w in h["wallets"]}
    ok("0x52908400098527886E0F7030069857D2E4169EE7" in wallets, "ETH wallet harvested")
    ok("TExampLeTronAddressDoNotUseXXXXXXX" in wallets, "TRON wallet harvested")
    banks = {b["value"] for b in h["bank_details"]}
    ok("DE89370400440532013000" in banks, "IBAN harvested (in bank context)")
    ok("DEUTDEFF" in banks, "SWIFT harvested")
    ok(any(c["upload_path"].endswith("/api/upload/kyc") and c["collects_credentials"]
           for c in h["credential_harvester"]), "credential-harvester upload path found")
    ok("deposit_flow" in h["service_flow"] and "withdraw_flow" in h["service_flow"],
       "service flow (deposit + withdraw) recognised")
    # a bare number with NO bank context must not be harvested as a bank account
    hno = en_harvest.harvest("<p>order number 123456789012</p>")
    ok(not hno["bank_details"], "bare number without bank context is NOT taken as an account")

    # base-rate exclusion in DOM harvest: the USDT token contract is never the operator's wallet
    hx = en_harvest.harvest("<p>contract TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t</p>")
    ok(not hx["wallets"], "USDT token contract excluded from DOM wallet harvest (base-rate)")

    # --- 5b. API-JSON mission mining (SPA money lives in XHR, not the DOM) -------------------
    # Shape a deposit API returns: the operator's `wallet` AND the token `contract` in one object.
    # SYNTHETIC values only (RULE 1) — the wallet is a placeholder; TR7... is Tether's PUBLIC
    # USDT-TRC20 token contract (a generic infrastructure constant, on the base-rate exclude list).
    WALLET_PLACEHOLDER = "T" + "A" * 33   # valid TRON format, obviously synthetic, not on any list
    api_bodies = [
        '{"success":true,"data":{"wallet":"' + WALLET_PLACEHOLDER + '","network":"TRC20",'
        '"contract":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"}}',
        '{"success":true,"data":{"bankName":"Example Bank","accountNumber":"10000001","accountName":"OPERATOR NAME"}}',
        '{"data":[{"name":"Support","url":"https://t.me/some_support"}]}',
    ]
    am = en_harvest.harvest_api(api_bodies)
    aw = {w["value"] for w in am["wallets"]}
    ok(WALLET_PLACEHOLDER in aw, "operator wallet mined from API 'wallet' field")
    ok("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" not in aw
       and any(e["value"].startswith("TR7") for e in am["excluded_base_rate"]),
       "token contract mined as EXCLUDED, never as the operator's wallet")
    ok(any(b.get("account_number") == "10000001" for b in am["bank_details"]),
       "VN bank account mined from API")
    ok(any("t.me/" in t for t in am["telegram"]), "telegram support handle mined from API")

    # the two en_engage helpers the case exposed exist and are data-driven
    import en_engage
    ok(len(en_engage.MODAL_DISMISS) >= 5 and "Nhắc lại sau" in en_engage.MODAL_DISMISS,
       "en_engage loaded modal_dismiss_labels (incl. the VN 'remind me later')")
    ok(hasattr(en_engage, "_dismiss_dialogs"), "en_engage has the modal-dismiss helper")

    # --- 6. en_report renders engagement artifacts into a citable section -------------------
    import en_report
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = os.path.join(td, "cases", "CASE-0001", "engage")
        os.makedirs(d)
        json.dump({"methods": {"vn_bank": {"bank": "Example Bank", "account_number": "10000001",
                   "account_name": "OPERATOR NAME", "description_memo_prefixes": ["note-a", "note-b"]},
                   "crypto_usdt": {"wallet": "T" + "A" * 33, "network": "TRC20",
                   "EXCLUDED_contract_base_rate": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t (contract)"}},
                   "anti_forensics": "history wiped daily"},
                  open(os.path.join(d, "payment_methods.json"), "w"))
        json.dump({"new_indicators": {"domains": {"site-b.example": "new sibling"}},
                   "cluster_basis": "first-party assertion"},
                  open(os.path.join(d, "cluster_expansion.json"), "w"))
        os.environ["INTEL_ROOT"] = td
        sec = en_report.build("CASE-0001")
        ok("Panel Engagement" in sec, "en_report renders a Panel Engagement section")
        ok("10000001" in sec and ("T" + "A" * 33) in sec, "en_report includes bank + wallet")
        ok("base-rate" in sec.lower() and "TR7NHqjeKQ" in sec,
           "en_report keeps the base-rate exclusion visible")
        ok(en_report.build("no-such-case").startswith("_No engagement"),
           "en_report degrades cleanly when a case has no engagement artifacts")

    # --- 6. INBOX pool is absent-safe + picks the right link --------------------------------
    import en_inbox
    os.environ["ENGAGE_INBOX_POOL"] = os.path.join(ROOT, "tests", "_no_such_pool.json")
    claim = en_inbox.claim()
    ok("error" in claim and "pool" in claim["error"], "absent inbox pool fails loudly, not silently")
    link = en_inbox._pick_link(
        "hi https://site.example/auth/verify?token=abc and https://tracker.other/x", "site.example")
    ok(link.startswith("https://site.example/auth/verify"), "confirm link chosen by target+confirm, not the tracker")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  {status:4} {label}")
    print(f"\n{'PASS' if f == 0 else 'FAIL'} — Engage skill ({p} passed, {f} failed)")
    raise SystemExit(1 if f else 0)
