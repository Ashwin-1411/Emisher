"""Parser for the ``Authentication-Results`` header (RFC 8601).

Example::

    Authentication-Results: mx.google.com;
        dkim=pass header.i=@example.com header.s=sel header.b=AbCd;
        spf=pass (google.com: domain of a@example.com designates 1.2.3.4 as permitted sender)
            smtp.mailfrom=a@example.com;
        dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
"""

from __future__ import annotations

from app.models import AuthMethodResult


def _split_outside_parens(text: str, sep: str) -> list[str]:
    """Split on ``sep`` but not inside ``( ... )`` comments or quoted strings."""
    parts: list[str] = []
    depth = 0
    quoted = False
    current: list[str] = []
    for ch in text:
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")" and depth:
            depth -= 1
        if ch == sep and depth == 0 and not quoted:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _strip_comments(text: str) -> tuple[str, str]:
    """Return (text without comments, concatenated comment text)."""
    out: list[str] = []
    comments: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
            if depth == 1:
                continue
        elif ch == ")" and depth:
            depth -= 1
            if depth == 0:
                comments.append("".join(buf))
                buf = []
                continue
        if depth:
            buf.append(ch)
        else:
            out.append(ch)
    return "".join(out), " ".join(comments)


def parse_authentication_results(value: str) -> tuple[str, list[AuthMethodResult]]:
    """Return ``(authserv_id, results)`` for one header value. Never raises."""
    segments = _split_outside_parens(" ".join(value.split()), ";")
    head, _ = _strip_comments(segments[0])
    authserv_id = head.split()[0].lower() if head.split() else ""
    results: list[AuthMethodResult] = []
    for segment in segments[1:]:
        cleaned, comment = _strip_comments(segment)
        tokens = cleaned.split()
        if not tokens or "=" not in tokens[0]:
            continue  # e.g. the literal "none" meaning no results
        method, _, result = tokens[0].partition("=")
        props: dict[str, str] = {}
        for token in tokens[1:]:
            key, eq, val = token.partition("=")
            if eq:
                props[key.lower()] = val.strip('"')
        results.append(
            AuthMethodResult(
                method=method.lower(), result=result.lower(), properties=props, comment=comment
            )
        )
    return authserv_id, results
