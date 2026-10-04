"""URL normalisation, redirector unwrapping and defanging. All pure functions, no network."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

from app.netutil import parse_ip, to_ascii_host

_DATA = Path(__file__).parent / "data"
_MAX_UNWRAP_DEPTH = 5  # nested wrappers exist (SafeLinks around a Google redirect); stop eventually


@lru_cache(maxsize=1)
def _redirectors() -> list[dict]:
    return json.loads((_DATA / "redirectors.json").read_text())["redirectors"]


@lru_cache(maxsize=1)
def shortener_hosts() -> frozenset[str]:
    return frozenset(json.loads((_DATA / "shorteners.json").read_text())["hosts"])


def normalize_url(url: str) -> str | None:
    """Canonical form used for de-duplication, or None if this is not an http(s) URL.

    * scheme and host lower-cased, host converted to punycode (so look-alike hosts compare equal);
    * default ports and the fragment removed;
    * ``www.example.com`` without a scheme is assumed to be http.
    """
    url = url.strip()
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    host = to_ascii_host(host)
    if ":" in host:  # IPv6 literal needs brackets again
        host = f"[{host}]"
    netloc = host
    if port and not (
        (parts.scheme.lower() == "http" and port == 80)
        or (parts.scheme.lower() == "https" and port == 443)
    ):
        netloc = f"{host}:{port}"
    if parts.username:
        # Keep userinfo: "https://paypal.com@evil.com" is a classic trick we must still detect.
        cred = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{cred}@{netloc}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def _decode_proofpoint_v2(url: str) -> str | None:
    """URL Defense v2 encodes the target in ``u=`` with '-' for '%' and '_' for '/'."""
    parts = urlsplit(url)
    if not (parts.hostname or "").endswith("urldefense.proofpoint.com") or "/v2/" not in parts.path:
        return None
    values = parse_qs(parts.query).get("u")
    if not values:
        return None
    return unquote(values[0].replace("_", "/").replace("-", "%"))


def _decode_proofpoint_v3(url: str) -> str | None:
    """URL Defense v3: ``https://urldefense.com/v3/__<target>__;<encoded-chars>!!...``."""
    parts = urlsplit(url)
    if (parts.hostname or "") != "urldefense.com":
        return None
    match = re.search(r"/v3/__(.+?)__;", url)
    return match.group(1) if match else None


def unwrap_once(url: str) -> str | None:
    """If ``url`` is a known redirector/wrapper, return the destination it carries, else None."""
    if (decoded := _decode_proofpoint_v2(url)) or (decoded := _decode_proofpoint_v3(url)):
        return decoded
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    for rule in _redirectors():
        if not re.search(rule["host"], host) or not re.search(rule["path"], parts.path):
            continue
        params = rule["param"] if isinstance(rule["param"], list) else [rule["param"]]
        query = parse_qs(parts.query)
        for name in params:
            if query.get(name):
                return query[name][0]  # parse_qs has already percent-decoded it
    return None


def unwrap(url: str) -> tuple[str, list[str]]:
    """Strip redirector layers. Returns ``(final_url, wrappers_removed)`` without any network I/O."""
    chain: list[str] = []
    current = url
    for _ in range(_MAX_UNWRAP_DEPTH):
        inner = unwrap_once(current)
        if not inner or inner == current:
            break
        chain.append(current)
        current = inner
    return current, chain


def defang(url: str) -> str:
    """Make a URL or domain safe to paste into a ticket or chat: ``hxxp://evil[.]com/path``."""
    url = re.sub(r"(?i)^http", "hxxp", url)
    parts = urlsplit(url)
    if parts.netloc:
        host = parts.netloc.replace(".", "[.]")
        return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    return url.replace(".", "[.]")  # bare domain or IP


def host_is_ip(host: str) -> bool:
    return parse_ip(host) is not None
