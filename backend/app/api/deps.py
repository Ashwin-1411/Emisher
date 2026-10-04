"""FastAPI dependencies: shared services, token auth, rate limiting, bounded body reading."""

from __future__ import annotations

import hashlib
import re
import secrets

from fastapi import HTTPException, Request

from app.services import Services


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


async def require_client(request: Request) -> str:
    """Authenticate the caller by the per-install token and apply the rate limit.

    This is a shared-secret check, not strong authentication: anyone who extracts the token
    from the extension's storage can use the API. docs/privacy.md and the backend README
    list what a production deployment would add (per-user OAuth, mTLS, signed requests).
    """
    services = get_services(request)
    settings = services.settings
    token = request.headers.get("X-API-Token", "")

    if not settings.auth_disabled:
        if not settings.api_tokens:
            raise HTTPException(503, "Server has no API_TOKENS configured")
        # compare_digest avoids leaking how many leading characters matched via timing.
        if not any(secrets.compare_digest(token, t) for t in settings.api_tokens):
            raise HTTPException(401, "Missing or invalid X-API-Token")

    client_id = (
        hashlib.sha256(token.encode()).hexdigest()[:16]
        if token
        else (request.client.host if request.client else "anonymous")
    )
    retry_after = services.limiter.check(client_id)
    if retry_after is not None:
        raise HTTPException(
            429, "Rate limit exceeded", headers={"Retry-After": str(int(retry_after) + 1)}
        )
    return client_id


async def read_body_limited(request: Request, max_bytes: int) -> bytes:
    """Read the request body in memory, refusing anything over ``max_bytes``.

    Checking Content-Length first rejects honest oversized uploads without reading them;
    counting while streaming also stops clients that lie about (or omit) the length.
    """
    limit_mb = max_bytes // (1024 * 1024)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise HTTPException(413, f"Upload exceeds the {limit_mb} MB limit")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise HTTPException(413, f"Upload exceeds the {limit_mb} MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def extract_form_file(content_type: str, body: bytes, field: str = "file") -> bytes | None:
    """Pull one file field out of a multipart/form-data body, entirely in memory.

    Starlette's own form parser spools uploads to temporary files on disk once they pass
    1 MB. We hold the (size-capped) body in RAM already, so a small purpose-built splitter
    keeps the "emails are never written to disk" promise.
    """
    marker = "boundary="
    if marker not in content_type:
        return None
    boundary = content_type.split(marker, 1)[1].split(";")[0].strip().strip('"').encode()
    delimiter = b"--" + boundary
    wanted = re.compile(rb'(?<![a-z])name="' + re.escape(field.encode()) + rb'"')
    for part in body.split(delimiter):
        head, sep, payload = part.partition(b"\r\n\r\n")
        if sep and wanted.search(head.lower()):
            return payload[:-2] if payload.endswith(b"\r\n") else payload
    return None


def extract_form_field(content_type: str, body: bytes, field: str) -> str | None:
    """Text value of a simple multipart form field (e.g. the consent flag)."""
    raw = extract_form_file(content_type, body, field)
    return raw.decode("utf-8", errors="replace").strip() if raw is not None else None
