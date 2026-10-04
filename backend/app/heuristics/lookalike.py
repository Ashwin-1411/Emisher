"""Lookalike-domain detection: punycode/IDN, homoglyphs, typosquats and brand keywords.

Strategy: reduce both the suspect domain and every known brand to a *skeleton* (a canonical
spelling where visually confusable characters collapse together), then compare. This catches
``paypa1.com``, ``rnicrosoft.com`` and ``pаypal.com`` (Cyrillic "а") with one mechanism, and an
edit-distance check catches simple typos such as ``paypall.com``.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from confusable_homoglyphs import confusables

from app.netutil import registered_domain, second_level_label, to_unicode_host

_BRANDS_FILE = Path(__file__).parent / "data" / "brands.json"

# ASCII look-alikes applied to BOTH sides of the comparison, so they only matter when the
# domain and the brand differ solely by these substitutions.
_ASCII_SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "|": "l", "$": "s"})
_MULTI_CHAR = (("rn", "m"), ("vv", "w"), ("cl", "d"))

STRONG_KINDS = {"homoglyph", "character_swap", "typosquat", "hyphenation", "brand_tld_swap"}


@dataclass(frozen=True)
class Brand:
    name: str
    domains: frozenset[str]


@dataclass(frozen=True)
class Lookalike:
    domain: str
    kind: (
        str  # homoglyph | character_swap | typosquat | hyphenation | brand_tld_swap | brand_keyword
    )
    brand: str
    detail: str

    @property
    def strong(self) -> bool:
        return self.kind in STRONG_KINDS


@lru_cache(maxsize=1)
def load_brands() -> list[Brand]:
    raw = json.loads(_BRANDS_FILE.read_text("utf-8"))["brands"]
    return [Brand(b["name"], frozenset(b["domains"])) for b in raw]


def _fold_unicode(text: str) -> str:
    """Map every non-ASCII character to its Latin look-alike where the Unicode confusables
    table knows one (Cyrillic а -> a, Greek ο -> o, ...)."""
    out = []
    for ch in unicodedata.normalize("NFKC", text.lower()):
        if ord(ch) < 128:
            out.append(ch)
            continue
        replacement = ch
        for entry in confusables.is_confusable(ch, greedy=True) or []:
            ascii_options = [h["c"] for h in entry["homoglyphs"] if h["c"].isascii()]
            if ascii_options:
                replacement = ascii_options[0].lower()
                break
        out.append(replacement)
    return "".join(out)


def skeleton(label: str) -> str:
    """Canonical lookalike-insensitive spelling of a domain label."""
    s = _fold_unicode(label).replace("-", "").translate(_ASCII_SUBSTITUTIONS)
    for src, dst in _MULTI_CHAR:
        s = s.replace(src, dst)
    return s


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (classic DP; labels are short so O(n*m) is fine)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.lower().split("."))


def check_domain(domain: str) -> list[Lookalike]:
    """Return lookalike findings for ``domain`` (ASCII/punycode form). Empty list if clean."""
    domain = domain.strip(".").lower()
    if not domain or "." not in domain:
        return []
    registered = registered_domain(domain)
    unicode_host = to_unicode_host(domain)
    sld_unicode = second_level_label(unicode_host)
    sld_skel = skeleton(sld_unicode)
    non_ascii = any(ord(c) > 127 for c in sld_unicode)
    findings: list[Lookalike] = []

    for brand in load_brands():
        if registered in brand.domains:
            return []  # it IS the brand (or a known brand domain): nothing to flag

    for brand in load_brands():
        brand_skel = skeleton(brand.name)
        if sld_skel == brand_skel:
            if sld_unicode == brand.name:
                kind, why = (
                    "brand_tld_swap",
                    f"uses the brand name on a different domain ({registered})",
                )
            elif non_ascii:
                kind, why = (
                    "homoglyph",
                    f"'{sld_unicode}' uses look-alike characters for '{brand.name}'",
                )
            elif "-" in sld_unicode and sld_unicode.replace("-", "") == brand.name:
                kind, why = (
                    "hyphenation",
                    f"'{sld_unicode}' is '{brand.name}' with hyphens inserted",
                )
            else:
                kind, why = (
                    "character_swap",
                    f"'{sld_unicode}' swaps characters to imitate '{brand.name}'",
                )
            findings.append(Lookalike(domain, kind, brand.name, why))
            continue
        ascii_sld = sld_skel
        limit = 1 if len(brand.name) < 9 else 2
        if len(brand.name) >= 5 and edit_distance(ascii_sld, brand_skel) <= limit:
            findings.append(
                Lookalike(
                    domain,
                    "typosquat",
                    brand.name,
                    f"'{sld_unicode}' is within {edit_distance(ascii_sld, brand_skel)} edit(s) of '{brand.name}'",
                )
            )
            continue
        host_labels = unicode_host.split(".")
        if len(brand.name) >= 5 and any(
            brand.name in skeleton(label) for label in host_labels[:-1]
        ):
            findings.append(
                Lookalike(
                    domain,
                    "brand_keyword",
                    brand.name,
                    f"contains the brand name '{brand.name}' but is not a {brand.name} domain",
                )
            )
    # Most specific first: homoglyph/swaps beat typosquat beat keyword; keep one per brand.
    order = {"homoglyph": 0, "character_swap": 1, "hyphenation": 2, "brand_tld_swap": 3,
             "typosquat": 4, "brand_keyword": 5}  # fmt: skip
    findings.sort(key=lambda f: order[f.kind])
    seen: set[str] = set()
    unique = []
    for f in findings:
        if f.brand not in seen:
            seen.add(f.brand)
            unique.append(f)
    return unique
