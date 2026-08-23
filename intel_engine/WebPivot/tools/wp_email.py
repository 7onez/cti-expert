"""wp_email — parse a victim's saved `.eml` so the same extractors that read a live page also read
the email a scam funnel actually sent.

The email is the least-obvious source in the file and often the best one, because it carries
selectors a web capture never shows and arrives WITH provenance — headers and a date:

  * a logo/hero image loaded from a shared multi-tenant CDN inside an automated
    "your deposit has been processed" notice is a FLEET selector recovered from a mailbox;
  * the Return-Path / From / DKIM `d=` domain is the operator's sending infrastructure;
  * tracking-pixel and List-Unsubscribe hosts name the ESP/CRM the operator provisioned.

`parse_eml()` returns the HTML body (so the normal WebPivot pipeline — trackers, wallets, telegram,
prose, footer — runs straight over it) plus a compact header-derived artifact dict. It makes NO
network calls: an `.eml` is passive evidence and reading it touches nothing of the subject's.
"""
import email
import re
from email import policy
from urllib.parse import urlparse

from wp_common import uniq, strip_www  # noqa

# Sending-infrastructure domains (ESP / transactional-mail providers). A Return-Path or DKIM on one
# of these is the mailer the operator rented, not the operator — recorded as context, never a
# same-operator pivot. Kept small and generic (public providers only, never case data).
ESP_DOMAINS = (
    "sendgrid.net", "amazonses.com", "mailgun.org", "mailgun.net", "sparkpostmail.com",
    "mandrillapp.com", "sendinblue.com", "sib.email", "mailjet.com", "postmarkapp.com",
    "mcsv.net", "mcdlv.net", "rsgsv.net", "list-manage.com", "cmail19.com", "cmail20.com",
    "sendpulse.com", "elasticemail.com", "mtasv.net", "customeriomail.com", "klaviyomail.com",
)

_HDR_HOST_RE = re.compile(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_URL_RE = re.compile(r"https?://[^\s<>\"'\)]+", re.I)
_IMG_SRC_RE = re.compile(r"""<img\b[^>]*\bsrc=["']?(https?://[^"'\s>]+)""", re.I)


def is_eml(path: str, head: bytes = b"") -> bool:
    """True when `path` is an email: a `.eml` extension, or a file that STARTS with an RFC 822
    header (so a `.txt`-saved message is still recognised). The header sniff is anchored to the top
    of the file so an HTML page that merely mentions "From:" somewhere is not misread as mail."""
    if path.lower().endswith(".eml"):
        return True
    h = head[:2048].decode("latin-1", "ignore") if isinstance(head, (bytes, bytearray)) else str(head)[:2048]
    return bool(re.match(
        r"(?is)^\s*(?:from|received|return-path|message-id|dkim-signature|mime-version|subject|to|date)\s*:",
        h))


def _decode_part(part) -> str:
    try:
        payload = part.get_content()               # policy.default decodes charset + transfer-encoding
        return payload if isinstance(payload, str) else payload.decode("utf-8", "ignore")
    except Exception:
        raw = part.get_payload(decode=True)
        return raw.decode("utf-8", "ignore") if raw else ""


def _host_of_addr(value: str):
    m = _HDR_HOST_RE.search(value or "")
    return strip_www(m.group(1).lower()) if m else None


def _hosts_in(value: str):
    out = []
    for u in _URL_RE.findall(value or ""):
        try:
            h = strip_www((urlparse(u).netloc or "").lower())
        except Exception:
            h = ""
        if h:
            out.append(h)
    return uniq(out)


def parse_eml(raw: bytes):
    """Parse email bytes → (html_body, artifacts). `html_body` is the text/html part (or a wrapped
    text/plain fallback) for the normal pipeline; `artifacts` is the header/CDN-derived selector
    dict. Never raises on a malformed message — a partial parse still yields whatever it read."""
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception:
        # last-ditch: treat the bytes as a plain HTML body so the run still produces something
        return raw.decode("utf-8", "ignore"), {}

    html_body, text_body = "", ""
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        try:
            ctype = part.get_content_type()
        except Exception:
            continue
        if ctype == "text/html" and not html_body:
            html_body = _decode_part(part)
        elif ctype == "text/plain" and not text_body:
            text_body = _decode_part(part)

    # sender / signing domains — the operator's OWN infra in a low-effort scam, an ESP otherwise
    sender_domains = uniq([h for h in (
        _host_of_addr(msg.get("Return-Path", "")),
        _host_of_addr(msg.get("From", "")),
        _host_of_addr(msg.get("Reply-To", "")),
        _host_of_addr(msg.get("Message-ID", "")),
    ) if h])
    dkim_domains = uniq([m.lower() for h in (msg.get_all("DKIM-Signature", []) or [])
                         for m in re.findall(r"\bd=([A-Za-z0-9.\-]+)", h or "")])
    unsub_hosts = _hosts_in(msg.get("List-Unsubscribe", "") or "")

    # embedded IMAGE urls (full, path kept) — the multi-tenant-CDN logo is the fleet selector; the
    # per-brand path template can enumerate the estate. Non-image links kept only as their host.
    image_urls = uniq(_IMG_SRC_RE.findall(html_body or ""))[:25]
    link_hosts = uniq([h for u in _URL_RE.findall(html_body or "")
                       for h in _hosts_in(u)])[:40]

    art = {
        "subject": (msg.get("Subject", "") or "").strip()[:200] or None,
        "sender_domains": sender_domains,
        "dkim_domains": dkim_domains,
        "unsubscribe_hosts": unsub_hosts,
        "image_urls": image_urls,
        "link_hosts": link_hosts,
    }
    art = {k: v for k, v in art.items() if v}

    html = html_body or (f"<pre>{text_body}</pre>" if text_body else "")
    return html, art


__all__ = ["is_eml", "parse_eml", "ESP_DOMAINS"]
