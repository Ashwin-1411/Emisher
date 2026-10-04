"""Run all offline heuristics and collect their signals."""

from __future__ import annotations

from app.heuristics.language import check_language
from app.heuristics.lookalike import check_domain, is_punycode
from app.heuristics.sender import check_display_name, check_header_mismatch
from app.models import HeuristicsReport, ParsedEmail, Signal, UrlFinding


def analyze_heuristics(
    email: ParsedEmail, urls: list[UrlFinding]
) -> tuple[HeuristicsReport, list[Signal]]:
    """Offline heuristics. Domain age needs RDAP and is evaluated separately by the pipeline."""
    report = HeuristicsReport()
    signals: list[Signal] = []

    signals += check_display_name(email)
    signals += check_header_mismatch(email)

    # --- sender domain lookalikes
    sender_domain = email.from_.domain if email.from_ else ""
    if sender_domain:
        if is_punycode(sender_domain):
            signals.append(
                Signal(
                    rule_id="punycode_domain",
                    detail=f"Sender domain {sender_domain} contains punycode labels",
                    context={"domain": sender_domain},
                )
            )
        for hit in check_domain(sender_domain):
            report.lookalikes.append(
                {"domain": hit.domain, "kind": hit.kind, "brand": hit.brand, "detail": hit.detail}
            )
            signals.append(
                Signal(
                    rule_id="lookalike_domain" if hit.strong else "brand_keyword_domain",
                    detail=hit.detail,
                    context={"domain": hit.domain, "brand": hit.brand},
                )
            )

    # --- link domain lookalikes (strong kinds only: keyword matches on links are too noisy)
    seen: set[str] = set()
    for url in urls:
        if not url.host or url.host in seen or "ip_host" in url.flags:
            continue
        seen.add(url.host)
        for hit in check_domain(url.host):
            if hit.strong:
                report.lookalikes.append(
                    {
                        "domain": hit.domain,
                        "kind": hit.kind,
                        "brand": hit.brand,
                        "detail": hit.detail,
                    }
                )
                signals.append(
                    Signal(
                        rule_id="lookalike_link_domain",
                        detail=hit.detail,
                        context={"domain": hit.domain, "brand": hit.brand},
                    )
                )

    lang_signals, matches = check_language(email)
    signals += lang_signals
    report.language_matches = matches
    return report, signals
