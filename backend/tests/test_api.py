from conftest import TOKEN, make_services, make_settings
from fastapi.testclient import TestClient
from helpers import load_fixture

from app.main import create_app


def multipart(raw: bytes) -> tuple[dict, bytes]:
    boundary = "XBOUNDARYX"
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.eml"\r\n'
            "Content-Type: message/rfc822\r\n\r\n"
        ).encode()
        + raw
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body


def test_health_needs_no_token(services) -> None:
    with TestClient(create_app(services.settings, services)) as c:
        assert c.get("/health").json() == {"status": "ok"}


def test_analyze_requires_token(services) -> None:
    with TestClient(create_app(services.settings, services)) as c:
        assert c.post("/api/v1/analyze", content=b"x").status_code == 401
        assert (
            c.post("/api/v1/analyze", content=b"x", headers={"X-API-Token": "wrong"}).status_code
            == 401
        )


def test_server_without_tokens_refuses(services) -> None:
    s = make_settings(api_tokens="")
    with TestClient(create_app(s, make_services(s))) as c:
        assert c.post("/api/v1/analyze", content=b"x").status_code == 503


def test_analyze_raw_body(client) -> None:
    r = client.post(
        "/api/v1/analyze?enrich=false",
        content=load_fixture("07_double_extension.eml"),
        headers={"Content-Type": "message/rfc822"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "PHISHING"
    assert body["attachments"][0]["sha256"]
    assert body["reasons"] and body["iocs"]
    assert "data" not in body["attachments"][0]  # attachment bytes never leave the server


def test_analyze_multipart(client) -> None:
    headers, body = multipart(load_fixture("02_display_name_spoof.eml"))
    r = client.post("/api/v1/analyze?enrich=false", content=body, headers=headers)
    assert r.status_code == 200 and r.json()["verdict"] == "SUSPICIOUS"


def test_multipart_without_file_field(client) -> None:
    headers, body = multipart(b"x")
    body = body.replace(b'name="file"', b'name="other"')
    assert client.post("/api/v1/analyze", content=body, headers=headers).status_code == 400


def test_empty_body_rejected(client) -> None:
    assert client.post("/api/v1/analyze", content=b"  ").status_code == 400


def test_upload_size_limit() -> None:
    s = make_settings(max_upload_bytes=1000)
    with TestClient(create_app(s, make_services(s)), headers={"X-API-Token": TOKEN}) as c:
        assert c.post("/api/v1/analyze", content=b"a" * 2000).status_code == 413
        # also when the client under-declares: chunked body without Content-Length
        assert c.post("/api/v1/analyze", content=iter([b"a" * 600, b"b" * 600])).status_code == 413


def test_rate_limit() -> None:
    s = make_settings(rate_limit_per_minute=3)
    with TestClient(create_app(s, make_services(s)), headers={"X-API-Token": TOKEN}) as c:
        codes = [
            c.post("/api/v1/analyze?enrich=false", content=load_fixture("01_legit.eml")).status_code
            for _ in range(4)
        ]
    assert codes == [200, 200, 200, 429]


def test_ioc_export(client) -> None:
    r = client.post(
        "/api/v1/analyze?enrich=false", content=load_fixture("05_link_text_mismatch.eml")
    )
    rid = r.json()["id"]
    as_json = client.get(f"/api/v1/reports/{rid}/iocs?format=json").json()
    assert any(i["type"] == "url" and i["defanged"].startswith("hxxp") for i in as_json)
    csv_resp = client.get(f"/api/v1/reports/{rid}/iocs?format=csv")
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert csv_resp.text.splitlines()[0] == "type,value,defanged,context"
    assert client.get("/api/v1/reports/nope/iocs").status_code == 404
    assert client.get(f"/api/v1/reports/{rid}").json()["id"] == rid


def test_enrich_false_makes_no_network_calls(client) -> None:
    # make_services' default transport raises on ANY outbound HTTP; success proves none happened.
    r = client.post("/api/v1/analyze?enrich=false", content=load_fixture("06_safelinks.eml"))
    assert r.status_code == 200
    assert r.json()["auth"]["live"]["performed"] is False


def test_cors_is_strict() -> None:
    s = make_settings(cors_allowed_origins="chrome-extension://abc")
    with TestClient(create_app(s, make_services(s))) as c:
        ok = c.options(
            "/api/v1/analyze",
            headers={"Origin": "chrome-extension://abc", "Access-Control-Request-Method": "POST"},
        )
        assert ok.headers.get("access-control-allow-origin") == "chrome-extension://abc"
        bad = c.options(
            "/api/v1/analyze",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
        )
        assert "access-control-allow-origin" not in bad.headers


def test_stage_failure_becomes_warning(client, monkeypatch) -> None:
    import app.pipeline as pipeline

    def boom(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(pipeline, "analyze_heuristics", boom)
    r = client.post("/api/v1/analyze?enrich=false", content=load_fixture("01_legit.eml"))
    assert r.status_code == 200
    assert any("heuristics" in w for w in r.json()["warnings"])
