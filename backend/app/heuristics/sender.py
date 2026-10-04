"""Sender-identity heuristics: display-name spoofing, Reply-To / Return-Path mismatch."""

from __future__ import annotations

import re

from app.heuristics.lookalike import load_brands
from app.models import ParsedEmail, Signal
from app.netutil import has_known_suffix, registered_domain

_ADDR_IN_NAME = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
_DOMAIN_IN_NAME = re.compile(r"\b((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b")


def _norm(text: str) -> str:
    """Lower-case letters and digits only, so 'Pay Pal' and 'PayPal' compare equal."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def check_display_name(email: ParsedEmail) -> list[Signal]:
    """Flag a display name that borrows a brand or a different domain than the real sender."""
    sender = email.from_
    if sender is None or not sender.display_name:
        return []
    signals: list[Signal] = []
    sender_domain = registered_domain(sender.domain)
    name_compact = _norm(sender.display_name)

    for brand in load_brands():
        if brand.name in name_compact and sender_domain not in brand.domains:
            # Short brand names ("ups", "irs") match inside ordinary words, so require a token match.
            if len(brand.name) <= 4 and brand.name not in re.split(
                r"\W+", sender.display_name.lower()
            ):
                continue
            signals.append(
                Signal(
                    rule_id="display_name_brand_spoof",
                    detail=f"Display name '{sender.display_name}' mentions {brand.name} but the sender is {sender.address}",
                    context={
                        "display_name": sender.display_name,
                        "domain": sender.domain,
                        "brand": brand.name,
                    },
                )
            )
            break  # one brand finding is enough

    shown = None
    if m := _ADDR_IN_NAME.search(sender.display_name):
        shown = m.group(1)
    else:
        for m in _DOMAIN_IN_NAME.finditer(sender.display_name):
            if has_known_suffix(m.group(1)):
                shown = m.group(1)
                break
    if shown and registered_domain(shown) != sender_domain:
        signals.append(
            Signal(
                rule_id="display_name_domain_mismatch",
                detail=f"Display name shows '{shown}' but the sender domain is {sender.domain}",
                context={"shown": shown, "domain": sender.domain},
            )
        )
    return signals


def check_header_mismatch(email: ParsedEmail) -> list[Signal]:
    """Reply-To and Return-Path should normally belong to the same organisation as From."""
    sender = email.from_
    if sender is None or not sender.domain:
        return []
    from_org = registered_domain(sender.domain)
    signals: list[Signal] = []
    if email.reply_to and email.reply_to.domain:
        reply_org = registered_domain(email.reply_to.domain)
        if reply_org != from_org:
            signals.append(
                Signal(
                    rule_id="reply_to_mismatch",
                    detail=f"Reply-To {email.reply_to.address} vs From {sender.address}",
                    context={"reply_domain": email.reply_to.domain, "domain": sender.domain},
                )
            )
    if email.return_path and email.return_path.domain:
        rp_org = registered_domain(email.return_path.domain)
        if rp_org != from_org:
            signals.append(
                Signal(
                    rule_id="return_path_mismatch",
                    detail=f"Return-Path {email.return_path.address} vs From {sender.address}",
                    context={"return_domain": email.return_path.domain, "domain": sender.domain},
                )
            )
    return signals
