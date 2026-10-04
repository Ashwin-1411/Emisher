"""DMARC identifier alignment (RFC 7489 section 3.1).

DMARC passes only if SPF *or* DKIM passes **and** the authenticated domain "aligns" with the
domain in the visible From header. That closes the loophole where an attacker passes SPF for
their own envelope domain while forging someone else's From address.
"""

from __future__ import annotations

from app.models import Alignment
from app.netutil import registered_domain


def compute_alignment(from_domain: str, authenticated_domain: str) -> Alignment:
    """Compare two domains in both DMARC modes.

    * strict  - the domains must be identical.
    * relaxed - they must share the same organisational (registrable) domain, so
      ``mail.example.com`` aligns with ``example.com``.
    """
    from_d = from_domain.strip(".").lower()
    auth_d = authenticated_domain.strip(".").lower()
    if not from_d or not auth_d:
        return Alignment(from_domain=from_d, authenticated_domain=auth_d)
    return Alignment(
        from_domain=from_d,
        authenticated_domain=auth_d,
        strict=from_d == auth_d,
        relaxed=registered_domain(from_d) == registered_domain(auth_d),
    )


def domain_of(identity: str) -> str:
    """Domain part of ``user@domain``, ``@domain`` or a bare domain."""
    identity = identity.strip().strip("<>")
    return identity.rsplit("@", 1)[-1].lower().strip(".")
