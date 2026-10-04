"""Models for analysis findings and the final ``Report`` returned by the API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


class Signal(BaseModel):
    """A raw observation emitted by an analysis module.

    Modules only *observe*; the scoring engine decides how much each ``rule_id`` is worth.
    Keeping detection and weighting apart means weights can be tuned in YAML without touching code.
    """

    rule_id: str
    detail: str  # technical, one line, for analysts
    context: dict[str, Any] = Field(default_factory=dict)  # fills the plain-English template


# ---------------------------------------------------------------- authentication
class AuthMethodResult(BaseModel):
    """One method result (spf / dkim / dmarc) from an Authentication-Results header."""

    method: str
    result: str  # pass, fail, softfail, neutral, none, temperror, permerror, ...
    properties: dict[str, str] = Field(default_factory=dict)  # e.g. {"smtp.mailfrom": "a@b.c"}
    comment: str = ""


class DeliveryAuth(BaseModel):
    """What the receiving provider stamped on the message at delivery time (primary signal)."""

    header_found: bool = False
    authserv_id: str = ""
    trusted: bool = False  # authserv-id matches the server that received the message
    results: list[AuthMethodResult] = Field(default_factory=list)
    note: str = ""

    def result_for(self, method: str) -> str | None:
        for r in self.results:
            if r.method == method:
                return r.result
        return None


class Alignment(BaseModel):
    """DMARC identifier alignment between the From domain and an authenticated domain."""

    from_domain: str
    authenticated_domain: str = ""
    relaxed: bool = False
    strict: bool = False


class LiveAuth(BaseModel):
    """Independent re-check against current DNS (secondary signal)."""

    performed: bool = False
    skipped_reason: str = ""
    connecting_ip: str = ""
    spf_result: str = ""
    spf_domain: str = ""
    spf_explanation: str = ""
    dkim_results: list[dict[str, Any]] = Field(default_factory=list)  # {domain, selector, result}
    dmarc_record: str = ""
    dmarc_policy: str = ""
    dmarc_adkim: str = "r"
    dmarc_aspf: str = "r"
    spf_alignment: Alignment | None = None
    dkim_alignment: list[Alignment] = Field(default_factory=list)
    dmarc_result: str = ""  # our own evaluation: pass / fail / none
    disagreements: list[str] = Field(default_factory=list)


class AuthReport(BaseModel):
    delivery: DeliveryAuth = Field(default_factory=DeliveryAuth)
    live: LiveAuth = Field(default_factory=LiveAuth)
    from_domain: str = ""
    # Alignment computed from the *delivery-time* results, so it works fully offline.
    spf_alignment: Alignment | None = None
    dkim_alignment: list[Alignment] = Field(default_factory=list)
    explanation: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- hops
class Hop(BaseModel):
    index: int  # 0 = oldest hop (bottom of the header block)
    raw: str
    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    protocol: str = ""
    timestamp: datetime | None = None
    delay_seconds: float | None = None  # since the previous (older) hop
    trusted: bool = False
    flags: list[str] = Field(default_factory=list)
    asn: str = ""
    country: str = ""


class HopReport(BaseModel):
    hops: list[Hop] = Field(default_factory=list)  # chronological, oldest first
    connecting_ip: str = ""  # topmost public IP: what the receiving server actually saw
    originating_ip: str = ""  # oldest public IP: unverifiable if below the trust boundary
    originating_ip_trusted: bool = False
    receiving_host: str = ""  # "by" host of the topmost hop: the provider that accepted the mail


# ---------------------------------------------------------------- urls
class UrlFinding(BaseModel):
    original: str
    url: str  # normalised and unwrapped
    defanged: str
    domain: str = ""  # registered domain (eTLD+1) of the target
    host: str = ""
    source: str = "text"  # html | text | attachment
    display_text: str = ""
    text_mismatch: bool = False
    unwrapped_from: list[str] = Field(default_factory=list)  # redirector hops removed
    expanded_from: str = ""  # set when a shortener was expanded over the network
    is_shortener: bool = False
    flags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- attachments
class MacroInfo(BaseModel):
    has_macros: bool = False
    autoexec: list[str] = Field(default_factory=list)
    suspicious: list[str] = Field(default_factory=list)


class AttachmentFinding(BaseModel):
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    detected_type: str  # our label from magic bytes, e.g. "pe", "pdf", "docx", "unknown"
    detected_mime: str = ""
    claimed_extension: str = ""
    nested_in: str | None = None
    flags: list[str] = Field(default_factory=list)
    macro: MacroInfo = Field(default_factory=MacroInfo)


# ---------------------------------------------------------------- heuristics
class DomainAge(BaseModel):
    domain: str
    registered: datetime | None = None
    age_days: int | None = None
    source: str = "rdap"


class HeuristicsReport(BaseModel):
    lookalikes: list[dict[str, str]] = Field(default_factory=list)  # {domain, kind, brand, detail}
    domain_ages: list[DomainAge] = Field(default_factory=list)
    language_matches: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- enrichment
class VtResult(BaseModel):
    kind: str  # "url" | "file"
    target: str  # defanged URL or sha256
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    found: bool = True
    permalink: str = ""
    cached: bool = False


class UrlscanResult(BaseModel):
    url: str  # defanged
    status: str  # done | pending | failed
    uuid: str = ""
    malicious: bool = False
    score: int = 0
    final_url: str = ""  # defanged
    screenshot_url: str = ""
    result_url: str = ""
    detail: str = ""  # why a scan failed, when urlscan says
    cached: bool = False


class EnrichmentReport(BaseModel):
    enabled: bool = False
    sources: dict[str, str] = Field(default_factory=dict)  # source -> ok | skipped: reason | error
    virustotal: list[VtResult] = Field(default_factory=list)
    urlscan: list[UrlscanResult] = Field(default_factory=list)


# ---------------------------------------------------------------- scoring + IOCs
class Reason(BaseModel):
    rule_id: str
    weight: int
    text: str  # plain-English explanation


class FiredRule(BaseModel):
    rule_id: str
    category: str
    weight: int
    description: str
    count: int = 1
    details: list[str] = Field(default_factory=list)


class IOC(BaseModel):
    type: str  # url | domain | ip | sha256 | sha1 | md5 | email
    value: str
    defanged: str
    context: str = ""


class EmailSummary(BaseModel):
    """Minimal metadata about the analysed message. No body content is kept."""

    subject: str = ""
    from_display: str = ""
    from_address: str = ""
    date: datetime | None = None
    message_id: str = ""
    attachment_count: int = 0


class Report(BaseModel):
    id: str
    created_at: datetime
    verdict: Verdict
    score: int
    reasons: list[Reason] = Field(default_factory=list)  # top reasons, heaviest first
    fired_rules: list[FiredRule] = Field(default_factory=list)
    overrides_applied: list[str] = Field(default_factory=list)
    email: EmailSummary = Field(default_factory=EmailSummary)
    auth: AuthReport = Field(default_factory=AuthReport)
    hops: HopReport = Field(default_factory=HopReport)
    urls: list[UrlFinding] = Field(default_factory=list)
    attachments: list[AttachmentFinding] = Field(default_factory=list)
    heuristics: HeuristicsReport = Field(default_factory=HeuristicsReport)
    enrichment: EnrichmentReport = Field(default_factory=EnrichmentReport)
    iocs: list[IOC] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
