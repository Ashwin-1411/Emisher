import json

from helpers import FIXTURES, StaticResolver, load_fixture

from app.auth_checks import check_auth
from app.auth_checks.alignment import compute_alignment
from app.auth_checks.live import parse_dmarc_record
from app.auth_checks.results_parser import parse_authentication_results
from app.hops import trace_hops
from app.parsing import parse_email


def test_parse_authentication_results() -> None:
    value = (
        "mx.google.com; dkim=pass header.i=@example.com header.s=sel header.b=AbCd; "
        "spf=pass (google.com: domain of a@example.com designates 1.2.3.4 as permitted sender; "
        "more) smtp.mailfrom=a@example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) "
        "header.from=example.com"
    )
    server, results = parse_authentication_results(value)
    assert server == "mx.google.com"
    by_method = {r.method: r for r in results}
    assert by_method["dkim"].properties["header.s"] == "sel"
    assert by_method["spf"].result == "pass"
    assert by_method["spf"].properties["smtp.mailfrom"] == "a@example.com"
    assert "designates 1.2.3.4" in by_method["spf"].comment
    assert by_method["dmarc"].properties["header.from"] == "example.com"


def test_parse_authentication_results_none_and_garbage() -> None:
    assert parse_authentication_results("mx.example.org; none") == ("mx.example.org", [])
    assert parse_authentication_results("")[1] == []
    server, results = parse_authentication_results("host; ((unbalanced spf=pass")
    assert server == "host"


def test_alignment_modes() -> None:
    a = compute_alignment("example.com", "mail.example.com")
    assert a.relaxed and not a.strict
    b = compute_alignment("example.com", "example.com")
    assert b.relaxed and b.strict
    c = compute_alignment("example.com", "spammer-bulk.net")
    assert not c.relaxed and not c.strict
    d = compute_alignment("a.co.uk", "b.co.uk")  # public suffix aware: co.uk is not an org
    assert not d.relaxed


def test_parse_dmarc_record() -> None:
    tags = parse_dmarc_record("v=DMARC1; p=Reject; adkim=s; pct=50")
    assert tags["p"] == "Reject" and tags["adkim"] == "s"


async def _auth(name: str, resolver=None, live=True):
    email = parse_email(load_fixture(name))
    hops, _ = trace_hops(email)
    return await check_auth(email, hops, resolver if live else None)


async def test_legit_email_passes_everything_and_live_dkim_verifies() -> None:
    report, signals = await _auth("01_legit.eml", StaticResolver())
    assert report.delivery.trusted
    assert signals == []
    assert report.live.performed
    assert report.live.spf_result == "pass"
    assert report.live.dkim_results[0]["result"] == "pass"  # real signature, verified offline
    assert report.live.dmarc_result == "pass" and report.live.dmarc_policy == "reject"
    assert report.spf_alignment and report.spf_alignment.strict
    assert report.live.disagreements == []


async def test_dmarc_alignment_failure() -> None:
    report, signals = await _auth("04_dmarc_alignment_fail.eml", StaticResolver())
    ids = {s.rule_id for s in signals}
    assert {"dmarc_fail", "spf_misaligned"} <= ids
    assert report.spf_alignment and not report.spf_alignment.relaxed
    assert report.live.spf_result == "pass"  # SPF really did pass, for the *other* domain
    assert report.live.dmarc_result == "fail"  # our own evaluation agrees with the provider
    assert report.live.disagreements == []


async def test_tampered_body_breaks_live_dkim_and_disagrees_with_delivery() -> None:
    raw = load_fixture("01_legit.eml").replace(b"March statement", b"March st4tement")
    email = parse_email(raw)
    hops, _ = trace_hops(email)
    report, _ = await check_auth(email, hops, StaticResolver())
    assert report.live.dkim_results[0]["result"] == "fail"
    assert any(d.startswith("DKIM:") for d in report.live.disagreements)


async def test_dns_failure_is_recorded_not_raised() -> None:
    resolver = StaticResolver(
        fail={"example.com", "_dmarc.example.com", "test._domainkey.example.com"}
    )
    report, _ = await _auth("01_legit.eml", resolver)
    assert report.live.spf_result == "temperror"
    assert report.live.dkim_results[0]["result"] == "temperror"


async def test_untrusted_authentication_results_are_ignored() -> None:
    raw = load_fixture("04_dmarc_alignment_fail.eml").replace(
        b"Authentication-Results: mx.example.org", b"Authentication-Results: evil.attacker.net"
    )
    email = parse_email(raw)
    hops, _ = trace_hops(email)
    report, signals = await check_auth(email, hops, None)
    assert not report.delivery.trusted
    ids = {s.rule_id for s in signals}
    assert "auth_results_untrusted" in ids and "dmarc_fail" not in ids


async def test_offline_mode_skips_live() -> None:
    report, _ = await _auth("01_legit.eml", live=False)
    assert not report.live.performed and report.live.skipped_reason


def test_zone_file_is_consistent() -> None:
    zone = json.loads((FIXTURES / "zone.json").read_text())
    assert "test._domainkey.example.com" in zone["TXT"]
