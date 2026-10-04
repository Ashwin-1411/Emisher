"""Shared test helpers: fixture loading and an in-memory DNS resolver."""

from __future__ import annotations

import json
from pathlib import Path

from app.auth_checks.resolver import DnsTemporaryError

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class StaticResolver:
    """A DnsResolver backed by a dict, so tests never touch the network.

    Names listed in ``fail`` raise a temporary error, to exercise failure handling.
    """

    def __init__(self, zone: dict | None = None, fail: set[str] | None = None) -> None:
        self.zone = zone if zone is not None else json.loads((FIXTURES / "zone.json").read_text())
        self.fail = fail or set()

    def _get(self, rtype: str, name: str) -> list:
        name = name.rstrip(".").lower()
        if name in self.fail:
            raise DnsTemporaryError(f"{rtype} {name}: simulated failure")
        return self.zone.get(rtype, {}).get(name, [])

    def txt(self, name: str) -> list[str]:
        return list(self._get("TXT", name))

    def a(self, name: str) -> list[str]:
        return list(self._get("A", name))

    def aaaa(self, name: str) -> list[str]:
        return list(self._get("AAAA", name))

    def mx(self, name: str) -> list[tuple[int, str]]:
        return [tuple(x) for x in self._get("MX", name)]  # type: ignore[misc]

    def ptr(self, reverse_name: str) -> list[str]:
        return list(self._get("PTR", reverse_name))
