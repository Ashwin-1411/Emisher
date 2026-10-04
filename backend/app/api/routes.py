"""HTTP routes under /api/v1."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.api.deps import extract_form_file, get_services, read_body_limited, require_client
from app.ioc import iocs_to_csv
from app.models import IOC, Report
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
