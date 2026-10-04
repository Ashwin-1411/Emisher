"""Enrichment tests: every external service is mocked; nothing touches the network."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import TOKEN, _instant_sleep, make_services, make_settings
from fastapi.testclient import TestClient
from helpers import load_fixture

from app.cache import MemoryCache
from app.enrichment.limits import DailyQuota, TokenBucket, request_with_retry
from app.enrichment.rdap import RdapClient
from app.enrichment.urlscan import UrlscanClient
from app.enrichment.virustotal import VirusTotalClient, VtUnavailable
from app.main import create_app
from app.pipeline import analyze_email

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def eicar_bytes() -> bytes:
    # The EICAR string is a harmless antivirus test pattern; built in memory, never written.
    return b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def eicar_email() -> bytes:
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "Sender <s@example.net>"
    msg["To"] = "student@example.org"
    msg["Subject"] = "test file"
    msg.set_content("attached")
    msg.add_attachment(
        eicar_bytes(), maintype="application", subtype="octet-stream", filename="eicar.com"
    )
    return msg.as_bytes()


def vt_payload(malicious=0, suspicious=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": 10,
                    "undetected": 5,
                }
            }
        }
    }


# ------------------------------------------------------------------ rate limiting + retry
async def test_token_bucket_waits_then_refuses_beyond_budget() -> None:
    now = [0.0]
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    bucket = TokenBucket(per_minute=4, capacity=2, clock=lambda: now[0], sleep=fake_sleep)
    assert await bucket.acquire(20) and await bucket.acquire(20)  # burst of 2
    assert slept == []
    assert await bucket.acquire(20)  # third must wait ~15 s (4 per minute)
    assert slept and 14 < slept[0] < 16
    assert not await bucket.acquire(5)  # next would need another 15 s > 5 s budget


def test_daily_quota() -> None:
    quota = DailyQuota(2)
    assert quota.try_use() and quota.try_use() and not quota.try_use()


async def test_retry_with_backoff_then_success() -> None:
    statuses = iter([503, 429, 200])
    sleeps: list[float] = []

    def handler(request):
        code = next(statuses)
        return httpx.Response(code, headers={"retry-after": "2"} if code == 429 else {})

    async def sleep(s):
        sleeps.append(s)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await request_with_retry(client, "GET", "https://x.test/", sleep=sleep)
    assert resp.status_code == 200 and len(sleeps) == 2
    assert 2.0 <= sleeps[1] <= 2.6  # Retry-After honoured (plus jitter)


async def test_retry_gives_up_on_transport_errors() -> None:
    def handler(request):
        raise httpx.ConnectTimeout("t")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.ConnectTimeout):
            await request_with_retry(
                client, "GET", "https://x.test/", retries=2, sleep=_instant_sleep
            )


# ------------------------------------------------------------------ VirusTotal
def make_vt(handler, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return VirusTotalClient("key", client, MemoryCache(), sleep=_instant_sleep, **kw)


async def test_vt_file_lookup_parses_and_caches() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["x-apikey"] == "key"
        return httpx.Response(200, json=vt_payload(malicious=62))

    vt = make_vt(handler)
    first = await vt.lookup_file(EICAR_SHA256)
    second = await vt.lookup_file(EICAR_SHA256)
    assert first.malicious == 62 and not first.cached
    assert second.cached and len(calls) == 1
    assert calls[0].url.path == f"/api/v3/files/{EICAR_SHA256}"


async def test_vt_url_id_is_urlsafe_base64() -> None:
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    vt = make_vt(handler)
    result = await vt.lookup_url("https://evil.example/a?b=1")
    expected = base64.urlsafe_b64encode(b"https://evil.example/a?b=1").decode().rstrip("=")
    assert seen == [f"/api/v3/urls/{expected}"]
    assert not result.found


async def test_vt_daily_quota_and_rate_skip() -> None:
    vt = make_vt(lambda r: httpx.Response(200, json=vt_payload()), daily_quota=1)
    await vt.lookup_file("a" * 64)
    with pytest.raises(VtUnavailable, match="quota"):
        await vt.lookup_file("b" * 64)


async def test_vt_server_error_is_unavailable_not_crash() -> None:
    vt = make_vt(lambda r: httpx.Response(403, json={}))
    with pytest.raises(VtUnavailable):
        await vt.lookup_file("c" * 64)


# ------------------------------------------------------------------ urlscan
def make_urlscan(handler, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return UrlscanClient("key", client, MemoryCache(), sleep=_instant_sleep, **kw), client


async def test_urlscan_submit_poll_and_parse() -> None:
    polls = iter([404, 404, 200])
    submitted = {}

    def handler(request):
        if request.method == "POST":
            submitted.update(__import__("json").loads(request.content))
            assert request.headers["api-key"] == "key"
            return httpx.Response(200, json={"uuid": "abc-123"})
        if next(polls) != 200:
            return httpx.Response(404)
        return httpx.Response(
            200,
            json={
                "page": {"url": "https://final.evil.example/x"},
                "task": {"screenshotURL": "https://urlscan.io/screenshots/abc-123.png"},
                "verdicts": {"overall": {"malicious": True, "score": 100}},
            },
        )

    scanner, _ = make_urlscan(handler)
    result = await scanner.scan("https://evil.example/")
    assert submitted == {"url": "https://evil.example/", "visibility": "unlisted"}
    assert result.status == "done" and result.malicious and result.score == 100
    assert result.final_url == "hxxps://final[.]evil[.]example/x"  # defanged for display
    assert result.screenshot_url.endswith("abc-123.png")
    again = await scanner.scan("https://evil.example/")
    assert again.cached


async def test_urlscan_visibility_is_configurable_and_validated() -> None:
    scanner, _ = make_urlscan(lambda r: httpx.Response(200, json={}), visibility="private")
    assert scanner.visibility == "private"
    bad, _ = make_urlscan(lambda r: httpx.Response(200, json={}), visibility="everyone")
    assert bad.visibility == "unlisted"


async def test_urlscan_pending_when_not_ready() -> None:
    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"uuid": "u1"})
        return httpx.Response(404)

    scanner, _ = make_urlscan(handler, max_wait=9, poll_interval=3)
    result = await scanner.scan("https://slow.example/")
    assert result.status == "pending" and result.result_url.endswith("/u1/")


async def test_urlscan_rejected_submission() -> None:
    scanner, _ = make_urlscan(
        lambda r: httpx.Response(400, json={"message": "DNS Error - Could not resolve domain"})
    )
    result = await scanner.scan("https://nonexistent.example/")
    assert result.status == "failed" and "resolve" in result.detail


# ------------------------------------------------------------------ RDAP
async def test_rdap_parses_registration_and_caches() -> None:
    now = datetime(2024, 3, 10, tzinfo=UTC)
    registered = now - timedelta(days=5)
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "events": [
                    {"eventAction": "last changed", "eventDate": "2024-03-09T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": registered.isoformat()},
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    rdap = RdapClient(client, MemoryCache(), sleep=_instant_sleep)
    age = await rdap.domain_age("evil.example", now=now)
    assert age.age_days == 5
    await rdap.domain_age("evil.example", now=now)
    assert calls == ["/domain/evil.example"]


async def test_rdap_unknown_domain() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    age = await RdapClient(client, MemoryCache(), sleep=_instant_sleep).domain_age("nope.example")
    assert age.age_days is None


# ------------------------------------------------------------------ pipeline integration
def routed(vt=None, urlscan=None, rdap=None):
    """Build one handler that serves all three mocked services."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "www.virustotal.com":
            return vt(request) if vt else httpx.Response(404)
        if host == "urlscan.io":
            return urlscan(request) if urlscan else httpx.Response(404)
        if host == "rdap.org":
            return rdap(request) if rdap else httpx.Response(404)
        raise AssertionError(f"unexpected host {host}")

    return handler


async def test_known_malicious_hash_forces_phishing() -> None:
    def vt(request):
        assert EICAR_SHA256 in request.url.path
        return httpx.Response(200, json=vt_payload(malicious=60))

    services = make_services(make_settings(vt_api_key="k", rdap_enabled=False), routed(vt=vt))
    report = await analyze_email(eicar_email(), services, enrich=True)
    assert hashlib.sha256(eicar_bytes()).hexdigest() == EICAR_SHA256
    assert report.verdict.value == "PHISHING"
    assert "known_malware_hash" in report.overrides_applied
    assert report.enrichment.virustotal[0].malicious == 60
    assert report.enrichment.sources["virustotal"] == "ok"
    assert report.enrichment.sources["urlscan"].startswith("skipped")


async def test_young_domain_from_rdap_adds_signal() -> None:
    registered = (datetime.now(UTC) - timedelta(days=4)).isoformat()

    def rdap(request):
        return httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": registered}]}
        )

    services = make_services(make_settings(), routed(rdap=rdap))
    report = await analyze_email(load_fixture("02_display_name_spoof.eml"), services, enrich=True)
    fired = {r.rule_id for r in report.fired_rules}
    assert "young_domain_sender" in fired
    assert report.heuristics.domain_ages[0].age_days == 4
    assert report.enrichment.sources["rdap"] == "ok"


async def test_urlscan_and_vt_url_signals() -> None:
    def vt(request):
        return httpx.Response(200, json=vt_payload(malicious=7))

    def urlscan(request):
        if request.method == "POST":
            return httpx.Response(200, json={"uuid": "z9"})
        return httpx.Response(
            200,
            json={
                "page": {"url": "http://login-verify.example.net/session?u=1"},
                "task": {},
                "verdicts": {"overall": {"malicious": True, "score": 90}},
            },
        )

    settings = make_settings(vt_api_key="k", urlscan_api_key="u", rdap_enabled=False)
    services = make_services(settings, routed(vt=vt, urlscan=urlscan))
    report = await analyze_email(load_fixture("05_link_text_mismatch.eml"), services, enrich=True)
    fired = {r.rule_id for r in report.fired_rules}
    assert {"vt_url_malicious", "urlscan_malicious"} <= fired
    assert report.verdict.value == "PHISHING"
    assert report.enrichment.urlscan[0].screenshot_url.endswith("z9.png")


async def test_enrichment_works_with_no_keys_and_reports_skips() -> None:
    services = make_services(make_settings(rdap_enabled=False))
    report = await analyze_email(load_fixture("05_link_text_mismatch.eml"), services, enrich=True)
    assert report.enrichment.sources["virustotal"].startswith("skipped")
    assert report.enrichment.sources["urlscan"].startswith("skipped")
    assert report.verdict.value == "SUSPICIOUS"  # offline verdict unaffected


async def test_service_outage_becomes_partial_not_failure() -> None:
    def vt(request):
        raise httpx.ConnectError("down")

    services = make_services(make_settings(vt_api_key="k", rdap_enabled=False), routed(vt=vt))
    report = await analyze_email(eicar_email(), services, enrich=True)
    assert report.enrichment.sources["virustotal"].startswith("partial")
    assert report.verdict.value in ("SAFE", "SUSPICIOUS", "PHISHING")  # still scored


async def test_enrich_false_skips_everything() -> None:
    services = make_services(
        make_settings(vt_api_key="k", urlscan_api_key="u")
    )  # would raise if called
    report = await analyze_email(eicar_email(), services, enrich=False)
    assert report.enrichment.sources == {"all": "skipped: enrich=false"}


# ------------------------------------------------------------------ consent upload endpoint
def form(fields: dict[str, bytes | str], filename_for: str = "file") -> tuple[dict, bytes]:
    boundary = "BB123"
    parts = b""
    for name, value in fields.items():
        value = value.encode() if isinstance(value, str) else value
        extra = '; filename="a.eml"' if name == filename_for else ""
        parts += (
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"{extra}\r\n\r\n'
            ).encode()
            + value
            + b"\r\n"
        )
    parts += f"--{boundary}--\r\n".encode()
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}, parts


def test_submit_requires_consent_and_matching_hash() -> None:
    uploads = []

    def vt(request):
        uploads.append(request)
        return httpx.Response(200, json={"data": {"id": "analysis-1"}})

    settings = make_settings(vt_api_key="k")
    services = make_services(settings, routed(vt=vt))
    with TestClient(create_app(settings, services), headers={"X-API-Token": TOKEN}) as c:
        url = f"/api/v1/attachments/{EICAR_SHA256}/submit"
        headers, body = form({"file": eicar_email()})
        assert c.post(url, content=body, headers=headers).status_code == 403  # no consent
        headers, body = form({"file": eicar_email(), "consent": "false"})
        assert c.post(url, content=body, headers=headers).status_code == 403
        assert uploads == []  # nothing left the server without consent

        headers, body = form({"file": eicar_email(), "consent": "true"})
        wrong = f"/api/v1/attachments/{'0' * 64}/submit"
        assert c.post(wrong, content=body, headers=headers).status_code == 404
        assert (
            c.post("/api/v1/attachments/xyz/submit", content=body, headers=headers).status_code
            == 422
        )

        ok = c.post(url, content=body, headers=headers)
        assert ok.status_code == 200 and ok.json()["analysis_id"] == "analysis-1"
        assert ok.json()["permalink"].endswith(EICAR_SHA256)
        assert len(uploads) == 1 and uploads[0].method == "POST"


def test_submit_without_vt_key_is_503() -> None:
    settings = make_settings()
    with TestClient(
        create_app(settings, make_services(settings)), headers={"X-API-Token": TOKEN}
    ) as c:
        headers, body = form({"file": eicar_email(), "consent": "true"})
        r = c.post(f"/api/v1/attachments/{EICAR_SHA256}/submit", content=body, headers=headers)
        assert r.status_code == 503
