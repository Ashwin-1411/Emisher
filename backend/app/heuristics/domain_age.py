"""Turn domain registration dates (from RDAP, see ``enrichment/rdap.py``) into signals."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models import DomainAge, Signal

YOUNG_DOMAIN_DAYS = 30  # phishing domains are typically used within days of registration


def age_in_days(registered: datetime, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    if registered.tzinfo is None:
        registered = registered.replace(tzinfo=UTC)
    return max(0, (now - registered).days)


def domain_age_signals(
    ages: list[DomainAge], sender_domain: str, link_domains: set[str]
) -> list[Signal]:
    """Flag sender and link domains registered fewer than 30 days ago."""
    signals: list[Signal] = []
    young_links = []
    for age in ages:
        if age.age_days is None or age.age_days >= YOUNG_DOMAIN_DAYS:
            continue
        ctx = {"domain": age.domain, "days": age.age_days}
        if age.domain == sender_domain:
            signals.append(
                Signal(
                    rule_id="young_domain_sender",
                    detail=f"{age.domain} registered {age.age_days} day(s) ago",
                    context=ctx,
                )
            )
        elif age.domain in link_domains:
            young_links.append(ctx)
    if young_links:
        signals.append(
            Signal(
                rule_id="young_domain_link",
                detail="; ".join(f"{c['domain']} ({c['days']} d)" for c in young_links),
                context=young_links[0],
            )
        )
    return signals
