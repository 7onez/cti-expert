#!/usr/bin/env python3
# cti-expert skill — ported/adapted from the Quarry OSINT toolkit
# (github.com/7onez/quarry): correlation_engine.py + entity_correlator.py.
"""pivot_suggest.py — read a case's findings and emit RANKED "what to pivot on next"
suggestions, so /branch and /crossref act on concrete correlations instead of guesswork.

Deterministic rules (all offline):
  * username variants  — leet-speak (4->a, 3->e...), incremental numbering, separator
                         (foo_bar ~ foobar), and exact cross-platform reuse
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


def _suggestion(pivot_type, target, priority, confidence, rationale, source=""):
    return {
        "pivot_type": pivot_type, "target": target, "priority": priority,
        "confidence": round(confidence, 2), "confidence_pct": int(round(confidence * 100)),
        "rationale": rationale, "source": source,
    }


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


def detect_username_variants(usernames):
    """usernames: list of (name, platform). Pairwise variant + exact-reuse detection."""
    out = []
    for i in range(len(usernames)):
        for j in range(i + 1, len(usernames)):
            ua, pa = usernames[i]
            ub, pb = usernames[j]
            if ua.lower() == ub.lower() and pa != pb:
                out.append(_suggestion(
                    'username_reuse', ub, 'high', 0.9,
                    f'Exact handle reused across platforms: "{ua}" ({pa}) = "{ub}" ({pb})', ua))
                continue
            rat = _username_variant_rationale(ua, ub)
            if rat:
                priority = 'high' if pa != pb else 'medium'
                conf = 0.85 if priority == 'high' else 0.65
                out.append(_suggestion(
                    'username_variant', ub, priority, conf,
                    f'{rat}: "{ua}" ({pa}) ~ "{ub}" ({pb})', ua))
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
