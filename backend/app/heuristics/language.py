"""Phishing-language keywords. A deliberately WEAK signal (see rules.yaml weights).

Real banks and cloud providers send "verify your account" emails too, so wording can only
nudge a score that other evidence has already raised; it must never decide a verdict alone.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path

from app.models import ParsedEmail, Signal

_PHRASES_FILE = Path(__file__).parent / "data" / "phrases.json"


@lru_cache(maxsize=1)
def _phrases() -> dict[str, list[str]]:
    data = json.loads(_PHRASES_FILE.read_text("utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    return " ".join(parser.parts)


def find_language_matches(email: ParsedEmail) -> dict[str, list[str]]:
    """Return ``{"urgency": [...], "credentials": [...]}`` of the phrases found."""
    haystack = " ".join([email.subject, email.text_body, html_to_text(email.html_body)]).lower()
    haystack = re.sub(r"\s+", " ", haystack)
    return {group: [p for p in phrases if p in haystack] for group, phrases in _phrases().items()}


def check_language(email: ParsedEmail) -> tuple[list[Signal], list[str]]:
    matches = find_language_matches(email)
    signals: list[Signal] = []
    for group, rule in (
        ("urgency", "urgency_language"),
        ("credentials", "credential_request_language"),
    ):
        found = matches.get(group, [])
        if found:
            signals.append(
                Signal(
                    rule_id=rule,
                    detail="Matched: " + ", ".join(found),
                    context={"example": found[0]},
                )
            )
    flat = [p for group in matches.values() for p in group]
    return signals, flat
