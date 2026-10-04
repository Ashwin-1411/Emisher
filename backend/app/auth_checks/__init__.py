"""Email authentication checks (SPF, DKIM, DMARC)."""

from app.auth_checks.checker import check_auth, parse_delivery_auth
from app.auth_checks.resolver import DnsResolver, DnsTemporaryError, SystemResolver

__all__ = [
    "DnsResolver",
    "DnsTemporaryError",
    "SystemResolver",
    "check_auth",
    "parse_delivery_auth",
]
