"""End-to-end check: every synthetic fixture gets its expected verdict and reasons."""

import json

import pytest
from conftest import make_services, make_settings
from helpers import FIXTURES, load_fixture

from app.pipeline import analyze_email

EXPECTED = json.loads((FIXTURES / "expected.json").read_text())


@pytest.mark.parametrize("name", sorted(EXPECTED))
@pytest.mark.parametrize("enrich", [False, True])
async def test_fixture_verdict(name: str, enrich: bool) -> None:
    expected = EXPECTED[name]
    report = await analyze_email(
        load_fixture(name), make_services(make_settings(rdap_enabled=False)), enrich=enrich
    )
    fired = {r.rule_id for r in report.fired_rules}

    assert report.verdict.value == expected["verdict"], (report.score, sorted(fired))
    assert set(expected["rules"]) <= fired, sorted(fired)
    if expected.get("exact_rules"):
        assert fired == set(expected["rules"])
    assert not report.warnings, report.warnings
    if report.verdict.value != "SAFE":
        assert report.reasons, "non-safe verdicts must explain themselves"
    for reason in report.reasons:
        assert "{" not in reason.text, f"unfilled template: {reason.text}"
