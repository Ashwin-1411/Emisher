"""DNS access for the authentication checks, behind a small interface.

Why an interface: SPF, DKIM key fetches and DMARC lookups are the only places we need DNS.
Funnelling them through one ``DnsResolver`` lets tests substitute a static zone (no network)
and lets the pipeline skip live checks entirely when ``enrich=false``.

The methods are synchronous because ``dkimpy`` and ``pyspf`` are synchronous libraries; the
callers run them in a worker thread via ``asyncio.to_thread``.
"""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver


class DnsTemporaryError(Exception):
    """A lookup failed for a reason that may go away (timeout, SERVFAIL). Not 'no such record'."""


class DnsResolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def a(self, name: str) -> list[str]: ...
    def aaaa(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[tuple[int, str]]: ...
    def ptr(self, reverse_name: str) -> list[str]: ...


class SystemResolver:
    """Resolver backed by dnspython and the machine's configured nameservers."""

    def __init__(self, timeout: float = 4.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = min(timeout, 2.0)

    def _query(self, name: str, rtype: str):  # noqa: ANN202 - dnspython answer type
        try:
            return list(self._resolver.resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DnsTemporaryError(f"{rtype} {name}: {type(exc).__name__}") from exc
        except dns.exception.DNSException as exc:  # malformed names etc.
            raise DnsTemporaryError(f"{rtype} {name}: {type(exc).__name__}") from exc

    def txt(self, name: str) -> list[str]:
        # A TXT record is a list of <=255-byte chunks that must be concatenated (RFC 7208 s3.3).
        return [
            b"".join(r.strings).decode("utf-8", errors="replace") for r in self._query(name, "TXT")
        ]

    def a(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "A")]

    def aaaa(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "AAAA")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return [
            (r.preference, r.exchange.to_text(omit_final_dot=True)) for r in self._query(name, "MX")
        ]

    def ptr(self, reverse_name: str) -> list[str]:
        return [r.target.to_text(omit_final_dot=True) for r in self._query(reverse_name, "PTR")]
