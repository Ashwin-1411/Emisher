from datetime import UTC, datetime, timedelta

import pytest
from helpers import load_fixture

from app.heuristics import age_in_days, check_domain, domain_age_signals
from app.heuristics.language import check_language
from app.heuristics.sender import check_display_name, check_header_mismatch
from app.models import DomainAge
from app.parsing import parse_email


@pytest.mark.parametrize(
    ("domain", "kind", "brand"),
    [
        ("xn--pypal-4ve.com", "homoglyph", "paypal"),  # Cyrillic a
        ("paypa1.com", "character_swap", "paypal"),
        ("rnicrosoft.com", "character_swap", "microsoft"),
        ("paypall.com", "typosquat", "paypal"),
        ("pay-pal.com", "hyphenation", "paypal"),
        ("paypal.xyz", "brand_tld_swap", "paypal"),
        ("paypal-secure-login.com", "brand_keyword", "paypal"),
        ("login.paypal.com.evil.net", "brand_keyword", "paypal"),
    ],
)
def test_lookalike_detection(domain: str, kind: str, brand: str) -> None:
    hits = check_domain(domain)
    assert hits and (hits[0].kind, hits[0].brand) == (kind, brand)


@pytest.mark.parametrize(
    "domain", ["paypal.com", "www.paypal.com", "example.com", "random-mailer.xyz", "amazon.co.uk"]
)
def test_legitimate_domains_are_clean(domain: str) -> None:
    assert check_domain(domain) == []


def test_display_name_spoof_fixture() -> None:
    email = parse_email(load_fixture("02_display_name_spoof.eml"))
    signals = check_display_name(email)
    assert [s.rule_id for s in signals] == ["display_name_brand_spoof"]
    assert signals[0].context["brand"] == "paypal"


def test_display_name_with_real_brand_domain_is_fine() -> None:
    email = parse_email(b'From: "PayPal" <service@paypal.com>\r\n\r\nx')
    assert check_display_name(email) == []


def test_display_name_showing_other_address() -> None:
    email = parse_email(b'From: "billing@bank.com" <x@evil.example>\r\n\r\nx')
    assert [s.rule_id for s in check_display_name(email)] == ["display_name_domain_mismatch"]


def test_short_brand_names_need_whole_word() -> None:
    email = parse_email(b'From: "Groups Support" <x@example.com>\r\n\r\nx')  # contains "ups"
    assert check_display_name(email) == []


def test_reply_to_and_return_path_mismatch() -> None:
    raw = b"From: a@example.com\r\nReply-To: b@gmail.com\r\nReturn-Path: <c@bounce.other.net>\r\n\r\nx"
    ids = {s.rule_id for s in check_header_mismatch(parse_email(raw))}
    assert ids == {"reply_to_mismatch", "return_path_mismatch"}
    same_org = b"From: a@example.com\r\nReply-To: b@mail.example.com\r\n\r\nx"
    assert check_header_mismatch(parse_email(same_org)) == []


def test_language_is_weak_but_detected() -> None:
    email = parse_email(load_fixture("02_display_name_spoof.eml"))
    signals, matches = check_language(email)
    assert {s.rule_id for s in signals} == {"urgency_language", "credential_request_language"}
    assert "verify your password" in matches
    clean = parse_email(load_fixture("01_legit.eml"))
    assert check_language(clean)[0] == []


def test_domain_age_signals() -> None:
    now = datetime(2024, 3, 10, tzinfo=UTC)
    young = DomainAge(domain="evil.example", registered=now - timedelta(days=3), age_days=3)
    old = DomainAge(domain="old.example", registered=now - timedelta(days=900), age_days=900)
    unknown = DomainAge(domain="who.example")
    signals = domain_age_signals([young, old, unknown], "evil.example", {"old.example"})
    assert [s.rule_id for s in signals] == ["young_domain_sender"]
    signals = domain_age_signals([young], "other.example", {"evil.example"})
    assert [s.rule_id for s in signals] == ["young_domain_link"]
    assert age_in_days(now - timedelta(days=29, hours=23), now) == 29
