from helpers import load_fixture

from app.hops import parse_received, trace_hops
from app.parsing import parse_email


def test_parse_received_standard() -> None:
    hop = parse_received(
        "from mail.example.com (mail.example.com [93.184.216.34]) by mx.example.org "
        "with ESMTPS id abc123 for <a@b.c>; Tue, 05 Mar 2024 10:00:05 +0000"
    )
    assert hop.from_host == "mail.example.com"
    assert hop.from_ip == "93.184.216.34"
    assert hop.by_host == "mx.example.org"
    assert hop.protocol == "ESMTPS"
    assert hop.timestamp is not None and hop.timestamp.hour == 10
    assert "malformed" not in hop.flags


def test_parse_received_ipv6_and_bare_ip_host() -> None:
    v6 = parse_received(
        "from smtp.x.org (smtp.x.org [IPv6:2001:db8::1]) by mx.y.org with ESMTP; "
        "Tue, 05 Mar 2024 10:00:05 +0000"
    )
    assert v6.from_ip == "2001:db8::1"
    bare = parse_received(
        "from [192.168.1.20] by relay.y.org with SMTP; Tue, 05 Mar 2024 10:00:05 +0000"
    )
    assert bare.from_ip == "192.168.1.20" and bare.from_host == ""


def test_parse_received_garbage_is_flagged_not_fatal() -> None:
    hop = parse_received("this is not a received header")
    assert "malformed" in hop.flags


def test_chain_is_chronological_and_trust_boundary_set() -> None:
    report, signals = trace_hops(parse_email(load_fixture("01_legit.eml")))
    assert [h.by_host for h in report.hops] == ["mail.example.com", "mx.example.org"]
    assert [h.trusted for h in report.hops] == [False, True]
    assert report.hops[1].delay_seconds == 2.0
    assert report.receiving_host == "mx.example.org"
    assert report.connecting_ip == "93.184.216.34"
    assert signals == []


def test_private_ip_at_origin_is_normal() -> None:
    report, _ = trace_hops(parse_email(load_fixture("01_legit.eml")))
    assert "private_ip_after_public" not in report.hops[0].flags  # internal first hop is expected


def test_forged_hop_detected() -> None:
    report, signals = trace_hops(parse_email(load_fixture("10_forged_received.eml")))
    by_index = {h.index: h for h in report.hops}
    assert "likely_forged" in by_index[1].flags
    assert "timestamp_out_of_order" in by_index[2].flags
    assert by_index[2].trusted and "likely_forged" not in by_index[2].flags
    ids = {s.rule_id for s in signals}
    assert {"hop_forged_suspected", "hop_timestamp_out_of_order"} <= ids
    # The originating IP comes from an untrusted hop, so it must be labelled unverified.
    assert report.originating_ip == "209.85.128.169" and not report.originating_ip_trusted
    assert report.connecting_ip == "151.101.1.69"


def test_private_ip_after_public_is_flagged() -> None:
    raw = (
        b"Received: from c.example.org (c [10.1.1.1]) by mx.example.org with SMTP; "
        b"Tue, 05 Mar 2024 10:00:10 +0000\r\n"
        b"Received: from b.example.net (b [8.8.8.8]) by c.example.org with SMTP; "
        b"Tue, 05 Mar 2024 10:00:05 +0000\r\n"
        b"From: x@example.net\r\n\r\nhi"
    )
    report, signals = trace_hops(parse_email(raw))
    assert "private_ip_after_public" in report.hops[1].flags
    assert any(s.rule_id == "hop_private_ip_unexpected" for s in signals)


def test_no_received_headers() -> None:
    report, signals = trace_hops(parse_email(b"From: a@example.com\r\n\r\nhi"))
    assert report.hops == [] and signals == []
