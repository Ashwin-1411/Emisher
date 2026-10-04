import httpx
from helpers import load_fixture

from app.parsing import parse_email
from app.urls import (
    analyze_urls,
    defang,
    expand_shorteners,
    extract_raw_links,
    normalize_url,
    resolve_candidates,
    unwrap,
)
from app.urls.extract import extract_from_html, extract_from_text


def test_html_extraction_keeps_display_text() -> None:
    links = extract_from_html('<p><a href="http://evil.com/x"><b>https://paypal.com</b></a></p>')
    assert links[0].url == "http://evil.com/x"
    assert links[0].text == "https://paypal.com"


def test_text_extraction_trims_punctuation() -> None:
    links = extract_from_text("See https://example.com/a?b=1, or (www.example.org/x). Thanks!")
    assert [link.url for link in links] == ["https://example.com/a?b=1", "www.example.org/x"]


def test_normalize() -> None:
    assert normalize_url("HTTP://Example.COM:80/a#frag") == "http://example.com/a"
    assert normalize_url("www.example.com") == "http://www.example.com/"
    assert normalize_url("mailto:a@b.c") is None
    assert normalize_url("javascript:alert(1)") is None
    assert normalize_url("https://pаypal.com/").startswith("https://xn--")  # Cyrillic a


def test_unwrap_safelinks_google_proofpoint_and_nesting() -> None:
    safe = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fx%3Fa%3D1&data=05"
    assert unwrap(safe)[0] == "https://evil.example/x?a=1"
    google = "https://www.google.com/url?q=https://evil.example/y&sa=D"
    assert unwrap(google)[0] == "https://evil.example/y"
    pp = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_path&d=x"
    assert unwrap(pp)[0] == "https://evil.example/path"
    nested = (
        "https://www.google.com/url?q="
        + "https%3A%2F%2Fnam.safelinks.protection.outlook.com%2F%3Furl%3Dhttps%253A%252F%252Fevil.example%252F"
    )
    final, chain = unwrap(nested)
    assert final == "https://evil.example/" and len(chain) == 2
    assert unwrap("https://example.com/")[1] == []


def test_defang() -> None:
    assert defang("http://evil.com/a.php?x=1") == "hxxp://evil[.]com/a.php?x=1"
    assert defang("https://sub.evil.co.uk") == "hxxps://sub[.]evil[.]co[.]uk"
    assert defang("evil.com") == "evil[.]com"


def test_text_mismatch_detected_only_when_text_looks_like_a_url() -> None:
    html = (
        '<a href="http://evil.example/login">https://www.paypal.com/signin</a>'
        '<a href="http://evil.example/two">Click here</a>'
        '<a href="https://www.paypal.com/ok">www.paypal.com</a>'
        '<a href="http://evil.example/three">Terms.Conditions apply</a>'
    )
    links = extract_from_html(html)
    findings, signals = analyze_urls(links)
    by_url = {f.url: f for f in findings}
    assert by_url["http://evil.example/login"].text_mismatch
    assert not by_url["http://evil.example/two"].text_mismatch
    assert not by_url["https://www.paypal.com/ok"].text_mismatch
    assert not by_url["http://evil.example/three"].text_mismatch  # "Terms.Conditions" is prose
    assert [s.rule_id for s in signals] == ["link_text_mismatch"]


def test_mismatch_is_judged_after_unwrapping() -> None:
    findings, signals = analyze_urls(
        extract_raw_links(parse_email(load_fixture("06_safelinks.eml")))
    )
    wrapped = [f for f in findings if f.unwrapped_from]
    assert len(wrapped) == 2
    assert {f.text_mismatch for f in wrapped} == {True, False}
    assert any(s.rule_id == "url_redirector_wrapped" for s in signals)


def test_ip_userinfo_and_dedup() -> None:
    html = (
        '<a href="http://192.0.2.7/x">a</a><a href="https://paypal.com@evil.example/">b</a>'
        '<a href="https://EXAMPLE.com/p">c</a><a href="https://example.com:443/p#x">d</a>'
    )
    findings, signals = analyze_urls(extract_from_html(html))
    flags = {f.url: f.flags for f in findings}
    assert "ip_host" in flags["http://192.0.2.7/x"]
    assert any("userinfo" in f for f in flags.values())
    assert len([f for f in findings if f.host == "example.com"]) == 1
    assert {"url_ip_host", "url_userinfo"} <= {s.rule_id for s in signals}


async def test_shortener_expansion_only_visits_shorteners() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert request.method == "HEAD"
        if request.url.host == "bit.ly":
            return httpx.Response(301, headers={"location": "https://tinyurl.com/abc"})
        if request.url.host == "tinyurl.com":
            return httpx.Response(302, headers={"location": "https://evil.example/landing"})
        raise AssertionError("must never contact the final destination")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        links = extract_from_text("go https://bit.ly/xyz now")
        candidates = resolve_candidates(links)
        assert candidates == ["https://bit.ly/xyz"]
        expansions = await expand_shorteners(candidates, client)
    assert expansions == {"https://bit.ly/xyz": "https://evil.example/landing"}
    assert calls == ["https://bit.ly/xyz", "https://tinyurl.com/abc"]
    findings, signals = analyze_urls(links, expansions)
    assert findings[0].url == "https://evil.example/landing"
    assert findings[0].is_shortener and findings[0].expanded_from
    assert any(s.rule_id == "url_shortener" for s in signals)


async def test_shortener_failure_is_graceful() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await expand_shorteners(["https://bit.ly/xyz"], client) == {}
