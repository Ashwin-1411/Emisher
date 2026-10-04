"""HTTP routes under /api/v1."""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.api.deps import (
    extract_form_field,
    extract_form_file,
    get_services,
    read_body_limited,
    require_client,
)
from app.api.schemas import SubmitResponse
from app.enrichment.virustotal import VtUnavailable
from app.ioc import iocs_to_csv
from app.models import IOC, Report
from app.parsing import parse_email
from app.pipeline import analyze_email
from app.services import Services

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_client)])
ServicesDep = Annotated[Services, Depends(get_services)]


async def _read_eml(request: Request, services: Services) -> bytes:
    body = await read_body_limited(request, services.settings.max_upload_bytes)
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        extracted = extract_form_file(content_type, body)
        if extracted is None:
            raise HTTPException(400, "Multipart upload must contain a 'file' field")
        body = extracted
    if not body.strip():
        raise HTTPException(400, "Empty request body")
    return body


@router.post("/analyze", response_model=Report)
async def analyze(
    request: Request,
    services: ServicesDep,
    enrich: Annotated[bool, Query(description="false skips every external lookup")] = True,
) -> Report:
    """Analyse an email sent as a multipart ``file`` upload or as a raw ``message/rfc822`` body."""
    raw = await _read_eml(request, services)
    report = await analyze_email(raw, services, enrich=enrich)
    services.reports.put(report)
    return report


@router.get("/reports/{report_id}", response_model=Report)
async def get_report(report_id: str, services: ServicesDep) -> Report:
    report = services.reports.get(report_id)
    if report is None:
        raise HTTPException(404, "Report not found or expired")
    return report


@router.get("/reports/{report_id}/iocs", response_model=None)
async def export_iocs(
    report_id: str,
    services: ServicesDep,
    format: Literal["json", "csv"] = "json",  # noqa: A002 - the query parameter name is the API
) -> list[IOC] | PlainTextResponse:
    report = services.reports.get(report_id)
    if report is None:
        raise HTTPException(404, "Report not found or expired")
    if format == "csv":
        return PlainTextResponse(
            iocs_to_csv(report.iocs),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="iocs-{report_id[:8]}.csv"'},
        )
    return report.iocs


@router.post("/attachments/{sha256}/submit", response_model=SubmitResponse)
async def submit_attachment(sha256: str, request: Request, services: ServicesDep) -> SubmitResponse:
    """Upload ONE attachment to VirusTotal, only with explicit consent.

    The caller re-sends the original ``.eml`` (multipart ``file``) plus ``consent=true``; we
    find the attachment whose SHA-256 matches the path and upload just that. Re-sending was
    chosen over keeping attachment bytes in server memory after /analyze: the server stays
    stateless, no attachment is ever retained, and the upload is tied to a request in which the
    user visibly agreed (see docs/privacy.md).
    """
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        raise HTTPException(422, "sha256 must be 64 lowercase hex characters")
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("multipart/form-data"):
        raise HTTPException(400, "Send multipart/form-data with 'file' and 'consent' fields")
    body = await read_body_limited(request, services.settings.max_upload_bytes)
    if (extract_form_field(content_type, body, "consent") or "").lower() != "true":
        raise HTTPException(403, "Explicit consent is required (consent=true)")
    raw = extract_form_file(content_type, body, "file")
    if not raw:
        raise HTTPException(400, "Multipart upload must contain a 'file' field")
    if not services.enricher.vt.enabled:
        raise HTTPException(503, "VirusTotal is not configured on this server")

    email = parse_email(raw)
    match = next(
        (a for a in email.attachments if hashlib.sha256(a.data).hexdigest() == sha256), None
    )
    if match is None:
        raise HTTPException(404, "No attachment with that SHA-256 in the supplied email")
    try:
        analysis_id, permalink = await services.enricher.vt.upload_file(match.filename, match.data)
    except VtUnavailable as exc:
        raise HTTPException(429, str(exc)) from exc
    return SubmitResponse(
        sha256=sha256,
        submitted=True,
        analysis_id=analysis_id,
        permalink=permalink,
        message="Uploaded to VirusTotal at your request. Results appear on the permalink shortly.",
    )
