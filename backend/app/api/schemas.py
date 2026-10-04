"""Request/response schemas that are specific to the HTTP layer.

The main response, ``Report``, lives in ``app.models`` because the extension mirrors it.
"""

from __future__ import annotations

from pydantic import BaseModel


class SubmitResponse(BaseModel):
    """Result of an explicit-consent upload of one attachment to VirusTotal."""

    sha256: str
    submitted: bool
    analysis_id: str = ""
    permalink: str = ""
    message: str = ""
