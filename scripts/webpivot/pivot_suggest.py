#!/usr/bin/env python3
# cti-expert skill — ported/adapted from the Quarry OSINT toolkit
# (github.com/7onez/quarry): correlation_engine.py + entity_correlator.py.
"""pivot_suggest.py — read a case's findings and emit RANKED "what to pivot on next"
suggestions, so /branch and /crossref act on concrete correlations instead of guesswork.

Deterministic rules (all offline):
  * username variants  — leet-speak (4->a, 3->e...), incremental numbering, separator
                         (foo_bar ~ foobar), and exact cross-platform reuse — each weighted
                         by the handle's RARITY grade (generic / moderate / rare), so a shared
                         common handle no longer outranks real leads (techniques/username-osint.md §7.2;
                         data: scripts/references/handle_rarity.json)
  * email<->name        — email local parts that match NO known person entity (alias lead)
  * temporal sync       — accounts/events across >=2 platforms inside one time window
  * domain clusters     — shared TLD, or shared base stem (foo-shop.top ~ fooshop.xyz)
  * CJK identity        — company-name stem (dep-free), pinyin romanization forms and
                          Simplified->Traditional; see techniques/china-recon.md §5

Fuzzy matching uses Levenshtein for short strings and trigram Jaccard for long ones,
exactly as the source engine does.

The CJK axis uses pypinyin and an OpenCC binding when importable and degrades gracefully
without them (the stem sub-axis is pure string work and always runs), so the script keeps
zero required dependencies. To enable the full axis:
  uv run --with pypinyin --with opencc-python-reimplemented pivot_suggest.py --cjk "张伟"

Usage:
  uv run pivot_suggest.py <case>/findings.json --pretty
  echo '{"social":[...],"emails":[...],"domains":[...]}' | uv run pivot_suggest.py -
  uv run pivot_suggest.py --usernames "d4rkc4t,darkcat,dark_cat" --pretty
  uv run pivot_suggest.py --domains "a-shop.top,ashop.xyz,a-shop.info"
  uv run pivot_suggest.py --cjk "张伟,深圳市某某科技有限公司" --pretty
  uv run pivot_suggest.py --xref "john.doe" "johndoe"      # similarity 0-100 between two values
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import os
import sys
import re
import json
import argparse
from datetime import datetime

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

_LEET_MAP = {'4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't'}
_PRIORITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}

# DATA: scripts/references/handle_rarity.json. This fallback is the minimum that keeps the grade
# working when the file is unreadable; it knows few tokens, so it grades FEWER handles generic —
# load_ref warns loudly, and tests/test_handle_rarity.py asserts the file (not this) is in use.
_RARITY_FALLBACK = {
    "grades": {"rare": {"priority_cap": "high", "confidence_scale": 1.0},
               "moderate": {"priority_cap": "medium", "confidence_scale": 0.7},
               "generic": {"priority_cap": "low", "confidence_scale": 0.2}},
    "limits": {"short_max_len": 4, "rare_min_len": 8, "rare_min_unknown_run": 4,
               "max_generic_digit_suffix": 4, "min_token_len": 3,
               "keyboard_walk_min_run": 4, "keyboard_walk_min_share": 0.6},
    "platform_default_patterns": [r"^(user|guest|member|player)[_.-]?\d{3,}$", r"^\d+$"],
    "common_given_names": ["john", "james", "david", "michael", "maria", "anna", "nguyen", "smith"],
    "common_words": ["the", "dark", "shadow", "king", "love", "cat", "dog", "wolf", "game", "pro"],
    "brand_tokens": ["binance", "telegram", "paypal", "support", "official"],
    "keyboard_walks": ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"],
    "public_figures": ["elon", "musk"],
}
_RARITY = None


def _rarity_refs():
    """handle_rarity.json through the engine's load_ref (one loader, loud fallback)."""
    global _RARITY
    if _RARITY is None:
        tools = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                              "..", "..", "intel_engine", "WebPivot", "tools"))
        if tools not in sys.path:
            sys.path.insert(0, tools)
        try:
            import wp_refs  # noqa: E402
            doc = wp_refs.load_ref(wp_refs.ref_path(__file__, "handle_rarity.json"), _RARITY_FALLBACK)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] handle_rarity.json not loaded ({exc}); using the embedded minimum",
                  file=sys.stderr)
            doc = dict(_RARITY_FALLBACK)
        lim = {**_RARITY_FALLBACK["limits"], **doc["limits"]}
        mn = int(lim["min_token_len"])
        brands = {t.lower() for t in doc["brand_tokens"] if len(t) >= mn}
        figures = {t.lower() for t in doc["public_figures"] if len(t) >= mn}
        vocab = {t.lower() for t in doc["common_given_names"] + doc["common_words"]
                 if len(t) >= mn} | brands | figures
        walks = [w.lower() for w in doc["keyboard_walks"] if w]
        _RARITY = {"grades": doc["grades"], "limits": lim, "vocab": vocab,
                   "names": {t.lower() for t in doc["common_given_names"]},
                   "brands": brands, "figures": figures,
                   "walks": walks + [w[::-1] for w in walks],
                   "patterns": [re.compile(p) for p in doc["platform_default_patterns"]]}
    return _RARITY


def _segment(s, vocab, max_tok):
    """Cheapest split of `s` into known tokens (cost 1) and unknown chars (cost 2 each).
    Returns [(piece, known_bool)] with consecutive unknown chars merged into runs."""
    n = len(s)
    best = [(0, None)] + [(float('inf'), None)] * n
    for i in range(1, n + 1):
        cost, back = best[i - 1][0] + 2, (i - 1, False)
        for j in range(max(0, i - max_tok), i - 2):
            if s[j:i] in vocab and best[j][0] + 1 < cost:
                cost, back = best[j][0] + 1, (j, True)
        best[i] = (cost, back)
    pieces, i = [], n
    while i > 0:
        j, known = best[i][1]
        pieces.append((s[j:i], known))
        i = j
    merged = []
    for piece, known in reversed(pieces):
        if merged and not known and not merged[-1][1]:
            merged[-1] = (merged[-1][0] + piece, False)
        else:
            merged.append((piece, known))
    return merged


def _keyboard_walk_share(flat, walks, min_run):
    """Share of `flat` covered by runs of >= min_run characters read along one keyboard row or
    column (`walks` already holds both directions). Input capped at 100 chars, so bounded work."""
    s = flat[:100]
    covered = [False] * len(s)
    i = 0
    while i < len(s):
        j = i
        while j < len(s) and any(s[i:j + 1] in w for w in walks):
            j += 1
        if j - i >= min_run:
            covered[i:j] = [True] * (j - i)
            i = j
        else:
            i += 1
    return sum(covered) / len(s) if s else 0.0


def handle_rarity(handle):
    """String-only rarity grade of a handle: {'grade': generic|moderate|rare, 'reason': str}.
    Adaptation of username-osint.md §7.2 steps 1-2 (P14 Perito et al., PETS 2011). It does not
    see copying, squatting or bulk-generated handles, nor how many unrelated owners use the
    string — the analyst's population check (§7.2 step 3) still decides."""
    r = _rarity_refs()
    lim = r["limits"]
    raw = (handle or "").strip().lower().lstrip("@")
    if any(p.search(raw) for p in r["patterns"]):
        return {"grade": "generic", "reason": "platform-default / placeholder pattern"}
    flat = _strip_separators(raw)
    walk_share = _keyboard_walk_share(flat, r["walks"], int(lim["keyboard_walk_min_run"]))
    if flat and walk_share >= float(lim["keyboard_walk_min_share"]):
        return {"grade": "generic", "reason": f"keyboard walk ({walk_share:.0%} of the handle "
                                              f"runs along a keyboard row or column)"}
    digits = re.search(r'\d*$', flat).group()
    base = _normalize_leet(flat[:len(flat) - len(digits)] if digits else flat)
    if len(base) <= int(lim["short_max_len"]):
        return {"grade": "generic", "reason": f"very short handle ({len(base)} chars before digits)"}
    max_tok = max((len(t) for t in r["vocab"]), default=1)
    parts = _segment(base, r["vocab"], max_tok)
    known = [p for p, k in parts if k]
    unknown = [p for p, k in parts if not k]
    brand = [t for t in known if t in r["brands"]]
    figure = [t for t in known if t in r["figures"]]
    if (brand or figure) and all(len(u) < int(lim["rare_min_unknown_run"]) for u in unknown):
        what = "; ".join(x for x in (
            f"brand/platform token(s) {'+'.join(brand)}" if brand else "",
            f"public-figure name {'+'.join(figure)}" if figure else "") if x)
        built = "+".join(known) + (f" + {len(digits)} digits" if digits else "")
        return {"grade": "generic", "reason": f"{what} with only generic parts ({built}) — "
                "impersonation/fan-style handle registered by many unrelated owners"}
    if not unknown:
        long_suffix = len(digits) > int(lim["max_generic_digit_suffix"])
        if len(known) == 1 and not long_suffix:
            return {"grade": "generic", "reason": f"single common token '{known[0]}'"
                    + (f" + {len(digits)} digits" if digits else "")}
        if 2 <= len(known) <= 3 and all(t in r["names"] for t in known) and not long_suffix:
            return {"grade": "generic", "reason": "personal-name skeleton " + "+".join(known)
                    + (f" + {len(digits)} digits" if digits else "")}
        return {"grade": "moderate", "reason": "compound of common tokens: " + "+".join(known)
                + (f" + {len(digits)}-digit suffix" if digits else "")}
    longest = max(len(u) for u in unknown)
    if len(base) >= int(lim["rare_min_len"]) and longest >= int(lim["rare_min_unknown_run"]):
        return {"grade": "rare", "reason": "uncommon token(s): " + ", ".join(
            u for u in unknown if len(u) >= int(lim["rare_min_unknown_run"]))}
    return {"grade": "moderate", "reason": "mostly common tokens, short uncommon part"}


_GRADE_ORDER = {'generic': 0, 'moderate': 1, 'rare': 2}


def _rarity_weighted(priority, confidence, rarity):
    """Cap priority and scale confidence by the rarity grade (handle_rarity.json → grades)."""
    g = _rarity_refs()["grades"][rarity["grade"]]
    cap = g["priority_cap"]
    if _PRIORITY_ORDER.get(cap, 1) > _PRIORITY_ORDER.get(priority, 1):
        priority = cap
    return priority, confidence * float(g["confidence_scale"])


def _normalize_leet(u: str) -> str:
    return ''.join(_LEET_MAP.get(c, c) for c in u.lower())


def _strip_trailing_numbers(u: str) -> str:
    return re.sub(r'\d+$', '', u)


def _strip_separators(u: str) -> str:
    return re.sub(r'[_\-.]', '', u)


def _levenshtein(a: str, b: str) -> int:
    a, b = a[:100], b[:100]
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[n]


def _trigrams(s: str) -> set:
    s = f"  {s} "
    return {s[i:i + 3] for i in range(len(s) - 2)}


def _trigram_similarity(a: str, b: str) -> float:
    ta, tb = _trigrams(a), _trigrams(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def fuzzy_match(a: str, b: str) -> float:
    """String similarity in [0,1]: Levenshtein for <8 chars, trigram Jaccard otherwise."""
    a, b = a.lower(), b.lower()
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    if len(a) < 8 or len(b) < 8:
        return 1.0 - _levenshtein(a, b) / max(len(a), len(b))
    return _trigram_similarity(a, b)


def _suggestion(pivot_type, target, priority, confidence, rationale, source="", **extra):
    s = {
        "pivot_type": pivot_type, "target": target, "priority": priority,
        "confidence": round(confidence, 2), "confidence_pct": int(round(confidence * 100)),
        "rationale": rationale, "source": source,
    }
    s.update(extra)
    return s


# --------------------------------------------------------------- detection rules
def _username_variant_rationale(a: str, b: str):
    al, bl = a.lower(), b.lower()
    if _normalize_leet(al) == _normalize_leet(bl) and al != bl:
        return 'leet-speak variant'
    ba, bb = _strip_trailing_numbers(al), _strip_trailing_numbers(bl)
    if ba and ba == bb and al != bl:
        return 'incremental numbering variant'
    if _strip_separators(al) == _strip_separators(bl) and al != bl:
        return 'separator variant'
    return None


def _rarity_note(rarity):
    return (f' — handle rarity {rarity["grade"].upper()} ({rarity["reason"]}); a string match is '
            f'a lead toward same controller, never a link (username-osint.md §7.1-7.2)')


def detect_username_variants(usernames):
    """usernames: list of (name, platform). Pairwise variant + exact-reuse detection, each
    weighted by the handle's rarity grade — the less distinctive side for a variant pair."""
    out = []
    for i in range(len(usernames)):
        for j in range(i + 1, len(usernames)):
            ua, pa = usernames[i]
            ub, pb = usernames[j]
            if ua.lower() == ub.lower() and pa != pb:
                rarity = handle_rarity(ua)
                priority, conf = _rarity_weighted('high', 0.9, rarity)
                out.append(_suggestion(
                    'username_reuse', ub, priority, conf,
                    f'Exact handle reused across platforms: "{ua}" ({pa}) = "{ub}" ({pb})'
                    + _rarity_note(rarity), ua, handle_rarity=rarity))
                continue
            rat = _username_variant_rationale(ua, ub)
            if rat:
                priority = 'high' if pa != pb else 'medium'
                conf = 0.85 if priority == 'high' else 0.65
                rarity = min((handle_rarity(ua), handle_rarity(ub)),
                             key=lambda r: _GRADE_ORDER[r["grade"]])
                priority, conf = _rarity_weighted(priority, conf, rarity)
                out.append(_suggestion(
                    'username_variant', ub, priority, conf,
                    f'{rat}: "{ua}" ({pa}) ~ "{ub}" ({pb})' + _rarity_note(rarity), ua,
                    handle_rarity=rarity))
    return out


def detect_email_name_mismatch(emails, known_names):
    """Email local parts that fuzzy-match NO known person entity → possible alias."""
    out = []
    if not known_names:
        return out
    for local in emails:
        cleaned = re.sub(r'[._\-]', ' ', local).lower()
        if not any(fuzzy_match(cleaned, n) > 0.7 for n in known_names):
            out.append(_suggestion(
                'email_name_mismatch', local, 'medium', 0.70,
                f'Email local part "{local}" matches no known person entity — possible alias/handle',
                ''))
    return out


def detect_temporal_sync(events, window_minutes=5):
    """events: list of (datetime, value, source). Cluster >=2 sources within a window."""
    out = []
    if len(events) < 2:
        return out
    events = sorted(events, key=lambda x: x[0])
    window = window_minutes * 60
    for i in range(len(events)):
        cluster = [events[i]]
        for j in range(i + 1, len(events)):
            if (events[j][0] - events[i][0]).total_seconds() <= window:
                cluster.append(events[j])
            else:
                break
        sources = {e[2] for e in cluster}
        if len(cluster) >= 2 and len(sources) >= 2:
            targets = ', '.join(e[1] for e in cluster[:3])
            out.append(_suggestion(
                'temporal_sync', targets, 'medium', 0.75,
                f'{len(cluster)} events across {len(sources)} sources within '
                f'{window_minutes}-minute window', ''))
    return out


def detect_domain_patterns(domains):
    """Shared-TLD groups (>=3) and shared base-stem clusters (>=2)."""
    out = []
    if len(domains) < 2:
        return out
    tld_groups = {}
    for d in domains:
        tld = d.rsplit('.', 1)[-1] if '.' in d else ''
        tld_groups.setdefault(tld, []).append(d)
    for tld, members in tld_groups.items():
        if len(members) >= 3:
            out.append(_suggestion(
                'domain_cluster', ', '.join(members[:5]), 'low', 0.60,
                f'{len(members)} domains share TLD ".{tld}"', ''))
    stem_groups = {}
    for d in domains:
        stem = d.split('.')[0]
        base = _strip_trailing_numbers(_strip_separators(stem))
        stem_groups.setdefault(base, []).append(d)
    for stem, members in stem_groups.items():
        if len(members) >= 2 and stem:
            out.append(_suggestion(
                'domain_stem_cluster', ', '.join(members[:5]), 'medium', 0.65,
                f'{len(members)} domains share base stem "{stem}"', ''))
    return out


# ------------------------------------------------------------------- CJK / pinyin axis
# A Chinese name has several valid Latin forms plus two orthographies, so enumerating one
# form finds one slice of the graph. See techniques/china-recon.md §5.

_HAN = re.compile(r'[㐀-䶿一-鿿豈-﫿]')
# Compound surnames must be tested before the single-char default.
_COMPOUND_SURNAMES = ('欧阳', '司马', '上官', '诸葛', '夏侯', '皇甫', '尉迟', '长孙',
                      '宇文', '慕容', '令狐', '南宫', '西门', '独孤')
# Boilerplate around the distinctive stem of a PRC company name.
_CN_CORP_SUFFIX = ('股份有限公司', '有限责任公司', '集团有限公司', '有限公司', '集团公司',
                   '集团', '公司', '企业', '工作室', '事务所', '中心', '厂', '店')
_CN_INDUSTRY_FILLER = ('信息技术', '网络科技', '电子商务', '供应链', '科技', '网络', '信息',
                       '技术', '贸易', '商贸', '实业', '投资', '咨询', '服务', '文化',
                       '传媒', '电子', '数码', '智能', '软件', '教育', '医疗', '金融',
                       '国际', '发展', '建设', '物流', '数据', '互联网')
_CN_LOCALITY = re.compile(r'^[一-鿿]{2,4}(省|市|区|县|自治区|自治州|新区)')


def has_han(s):
    return bool(_HAN.search(s or ''))


def cn_company_stem(name):
    """Strip locality prefix, corporate form and industry filler -> distinctive stem.

    深圳市某某科技有限公司 -> 某某 . The stem is what is worth searching; the filler
    matches tens of thousands of unrelated firms.
    """
    s = (name or '').strip()
    s = _CN_LOCALITY.sub('', s)
    for suf in _CN_CORP_SUFFIX:            # longest-first via tuple order
        if s.endswith(suf):
            s = s[:-len(suf)]
            break
    for filler in _CN_INDUSTRY_FILLER:
        s = s.replace(filler, '')
    return s.strip()


def _split_surname(name):
    for cs in _COMPOUND_SURNAMES:
        if name.startswith(cs):
            return cs, name[len(cs):]
    return name[:1], name[1:]


def _romanize(text):
    """Toneless pinyin syllables. Returns [] when pypinyin is absent (axis degrades)."""
    try:
        from pypinyin import lazy_pinyin
    except ImportError:
        return []
    try:
        return [s for s in lazy_pinyin(text) if s]
    except Exception:
        return []


def _to_traditional(text):
    """Simplified -> Traditional, or None when no converter is installed."""
    for mod, ctor in (('opencc', lambda m: m.OpenCC('s2t')),
                      ('opencc_python_reimplemented', lambda m: m.OpenCC('s2t'))):
        try:
            m = __import__(mod)
            conv = ctor(m).convert(text)
            return conv if conv and conv != text else None
        except Exception:
            continue
    return None


def detect_cjk_variants(cn_names):
    """Romanization / orthography / stem variants for CJK names and company names."""
    out = []
    for raw in cn_names:
        name = (raw or '').strip()
        if not name or not has_han(name):
            continue

        stem = cn_company_stem(name)
        is_company = stem and stem != name
        if is_company:
            out.append(_suggestion(
                'cn_company_stem', stem, 'high', 0.82,
                f'distinctive stem of "{name}" after stripping locality/form/industry filler '
                f'— search this, not the full name', name))

        subject = stem if is_company else name
        syllables = _romanize(subject)
        if syllables:
            joined = ''.join(syllables)
            forms = {joined, ' '.join(syllables), '-'.join(syllables), '_'.join(syllables)}
            if not is_company and len(syllables) >= 2:
                surname, given = _split_surname(subject)
                sy_s, sy_g = _romanize(surname), _romanize(given)
                if sy_s and sy_g:
                    # given-name-first order, the usual Western rendering
                    forms.add(''.join(sy_g + sy_s))
                    forms.add(' '.join(sy_g) + ' ' + ''.join(sy_s))
                    forms.add(''.join(sy_g)[:1] + '.' + ''.join(sy_s))
                    forms.add(''.join(s[0] for s in syllables))          # initials
            for f in sorted(x for x in forms if x and x != subject):
                out.append(_suggestion(
                    'cn_romanization', f,
                    'medium' if is_company else 'high',
                    0.70 if is_company else 0.78,
                    f'pinyin form of "{subject}" — enumerate as handle/email local-part', name))
        else:
            out.append(_suggestion(
                'cn_romanization_unavailable', subject, 'medium', 0.60,
                'pypinyin not installed — romanization axis skipped. '
                'Install: uv tool install pypinyin (or uv run --with pypinyin)', name))

        trad = _to_traditional(subject)
        if trad:
            out.append(_suggestion(
                'cn_traditional', trad, 'medium', 0.72,
                f'Traditional orthography of "{subject}" — HK/TW/overseas properties often '
                f'register under this form', name))
    return out


# ------------------------------------------------------------------- findings load
def _val(item, *keys):
    if isinstance(item, dict):
        for k in keys:
            if item.get(k):
                return item[k]
        return ''
    return str(item)


def load_findings(findings):
    usernames, emails, names, domains, events, cn_names = [], [], [], [], [], []
    for it in findings.get('social', []) or []:
        u = _val(it, 'username', 'value', 'handle')
        if u:
            usernames.append((u, _val(it, 'platform', 'network') or 'unknown'))
        ts = it.get('timestamp') if isinstance(it, dict) else None
        if ts:
            try:
                dt = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
                events.append((dt, u, _val(it, 'platform', 'network') or 'unknown'))
            except ValueError:
                pass
    for it in findings.get('emails', []) or []:
        addr = _val(it, 'value', 'email', 'address') or (it if isinstance(it, str) else '')
        local = addr.split('@')[0] if '@' in addr else ''
        if local:
            emails.append(local)
    for key in ('persons', 'people', 'names'):
        for it in findings.get(key, []) or []:
            n = _val(it, 'value', 'name', 'full_name')
            if n:
                # CJK names have no Latin word structure — route them to the pinyin axis
                # instead of lower-casing them into the email/name comparison.
                if has_han(n):
                    cn_names.append(n.strip())
                else:
                    names.append(n.lower())
    for key in ('cn_names', 'organizations', 'orgs'):
        for it in findings.get(key, []) or []:
            n = _val(it, 'value', 'name', 'full_name')
            if n and has_han(n):
                cn_names.append(n.strip())
    for it in findings.get('domains', []) or []:
        d = _val(it, 'value', 'domain', 'host')
        if d:
            domains.append(d.lower())
    return usernames, emails, names, domains, events, sorted(set(cn_names))


def suggest_all(findings):
    usernames, emails, names, domains, events, cn_names = load_findings(findings)
    raw = []
    raw += detect_username_variants(usernames)
    raw += detect_email_name_mismatch(emails, names)
    raw += detect_temporal_sync(events)
    raw += detect_domain_patterns(domains)
    raw += detect_cjk_variants(cn_names)

    # dedup on (pivot_type, target); keep highest confidence
    seen = {}
    for p in raw:
        key = (p['pivot_type'], p['target'])
        if key not in seen or p['confidence'] > seen[key]['confidence']:
            seen[key] = p
    suggestions = sorted(
        seen.values(),
        key=lambda p: (_PRIORITY_ORDER.get(p['priority'], 1), -p['confidence']))

    by_type, by_prio = {}, {}
    for p in suggestions:
        by_type[p['pivot_type']] = by_type.get(p['pivot_type'], 0) + 1
        by_prio[p['priority']] = by_prio.get(p['priority'], 0) + 1
    return {"suggestions": suggestions,
            "summary": {"count": len(suggestions), "by_type": by_type, "by_priority": by_prio,
                        "inputs": {"usernames": len(usernames), "emails": len(emails),
                                   "names": len(names), "domains": len(domains),
                                   "timestamped": len(events), "cn_names": len(cn_names)}}}


def _csv(s):
    return [x.strip() for x in (s or '').split(',') if x.strip()]


def main():
    ap = argparse.ArgumentParser(description="Rank 'what to pivot on next' from case findings.")
    ap.add_argument("findings", nargs="?", help="findings JSON file, or '-' for stdin")
    ap.add_argument("--usernames", help="comma-separated handles (ad-hoc, no file)")
    ap.add_argument("--emails", help="comma-separated emails (ad-hoc)")
    ap.add_argument("--names", help="comma-separated known person names (ad-hoc)")
    ap.add_argument("--domains", help="comma-separated domains (ad-hoc)")
    ap.add_argument("--cjk", help="comma-separated CJK person/company names (ad-hoc) — "
                                  "pinyin, Traditional and company-stem variants")
    ap.add_argument("--xref", nargs=2, metavar=("A", "B"),
                    help="print string similarity 0-100 between two values and exit")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("-o", "--out", help="write JSON to file")
    args = ap.parse_args()

    if args.xref:
        print(round(fuzzy_match(args.xref[0], args.xref[1]) * 100, 1))
        return

    findings = {}
    if args.findings == "-":
        findings = json.loads(sys.stdin.read() or "{}")
    elif args.findings:
        findings = json.load(open(args.findings, encoding="utf-8"))
    # ad-hoc CLI overlays (merge into findings)
    if args.usernames:
        findings.setdefault("social", []).extend(
            {"username": u, "platform": f"cli{i}"} for i, u in enumerate(_csv(args.usernames)))
    if args.emails:
        findings.setdefault("emails", []).extend({"value": e} for e in _csv(args.emails))
    if args.names:
        findings.setdefault("persons", []).extend({"value": n} for n in _csv(args.names))
    if args.domains:
        findings.setdefault("domains", []).extend({"value": d} for d in _csv(args.domains))
    if args.cjk:
        findings.setdefault("cn_names", []).extend({"value": n} for n in _csv(args.cjk))

    result = suggest_all(findings)
    s = result["summary"]
    print(f"pivot_suggest: {s['count']} suggestion(s) "
          f"[{', '.join(f'{k}:{v}' for k, v in s['by_priority'].items()) or 'none'}]",
          file=sys.stderr)
    text = json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
