"""Turn raw links into normalised, unwrapped, de-duplicated findings plus signals."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.models import Signal, UrlFinding
from app.netutil import has_known_suffix, registered_domain
from app.urls.extract import RawLink
from app.urls.normalize import defang, host_is_ip, normalize_url, shortener_hosts, unwrap

# A domain-looking token inside link text, e.g. "www.paypal.com/login" or "https://bank.com".
_TEXT_DOMAIN_RE = re.compile(
    r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/?#]\S*)?"
)


def _text_domain(text: str) -> str:
    """Registered domain that the visible link text *claims* to point at, or '' if none."""
    for match in _TEXT_DOMAIN_RE.finditer(text):
        host = match.group(1).lower()
        if has_known_suffix(host):
            return registered_domain(host)
    return ""


def resolve_candidates(links: list[RawLink]) -> list[str]:
    """Normalised, unwrapped URLs whose host is a known shortener (inputs for network expansion)."""
    out: list[str] = []
    for link in links:
        n = normalize_url(link.url)
        if not n:
            continue
        final, _ = unwrap(n)
        final = normalize_url(final) or n
        if (urlsplit(final).hostname or "") in shortener_hosts() and final not in out:
            out.append(final)
    return out


def analyze_urls(
    links: list[RawLink], expansions: dict[str, str] | None = None
) -> tuple[list[UrlFinding], list[Signal]]:
    """Build findings for every distinct destination and emit signals for the suspicious ones.

    ``expansions`` maps shortener URL -> its resolved destination (from ``expand_shorteners``);
    pass None when no network lookups were made.
    """
    expansions = expansions or {}
    findings: dict[str, UrlFinding] = {}
    for link in links:
        normalized = normalize_url(link.url)
        if not normalized:
            continue
        final, wrappers = unwrap(normalized)
        final = normalize_url(final) or normalized
        expanded_from = ""
        if final in expansions and (target := normalize_url(expansions[final])):
            expanded_from, final = final, target

        parts = urlsplit(final)
        host = (parts.hostname or "").lower()
        domain = host if host_is_ip(host) else registered_domain(host)
        shown = _text_domain(link.text) if link.text else ""
        mismatch = bool(shown and shown != domain)

        flags: list[str] = []
        if host_is_ip(host):
            flags.append("ip_host")
        if parts.username:
            flags.append("userinfo")
        if host.startswith("xn--") or ".xn--" in host:
            flags.append("punycode_host")
        original_host = urlsplit(expanded_from or final).hostname or ""
        is_short = original_host in shortener_hosts()
        if is_short:
            flags.append("shortener")
        if wrappers:
            flags.append("redirector_wrapped")

        existing = findings.get(final)
        if existing is None:
            findings[final] = UrlFinding(
                original=link.url,
                url=final,
                defanged=defang(final),
                domain=domain,
                host=host,
                source=link.source,
                display_text=link.text if mismatch or link.text else "",
                text_mismatch=mismatch,
                unwrapped_from=[defang(w) for w in wrappers],
                expanded_from=defang(expanded_from) if expanded_from else "",
                is_shortener=is_short,
                flags=flags,
            )
        elif mismatch and not existing.text_mismatch:
            existing.text_mismatch = True
            existing.display_text = link.text

    result = list(findings.values())
    return result, _signals(result)


def _signals(findings: list[UrlFinding]) -> list[Signal]:
    out: list[Signal] = []
    mism = [f for f in findings if f.text_mismatch]
    if mism:
        f = mism[0]
        out.append(
            Signal(
                rule_id="link_text_mismatch",
                detail="; ".join(
                    f"shows '{m.display_text}' but goes to {m.defanged}" for m in mism
                ),
                context={
                    "shown": _text_domain(f.display_text),
                    "actual": f.domain,
                    "count": len(mism),
                },
            )
        )
    for flag, rule in (
        ("ip_host", "url_ip_host"),
        ("userinfo", "url_userinfo"),
        ("shortener", "url_shortener"),
        ("redirector_wrapped", "url_redirector_wrapped"),
    ):
        hit = [f for f in findings if flag in f.flags]
        if hit:
            out.append(
                Signal(
                    rule_id=rule,
                    detail=", ".join(f.defanged for f in hit[:3]),
                    context={"count": len(hit), "example": hit[0].domain},
                )
            )
    return out
