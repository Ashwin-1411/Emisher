import pytest
import yaml

from app.models import Signal, Verdict
from app.scoring import evaluate, load_rules
from app.scoring.engine import DEFAULT_RULES_PATH


def sig(rule_id: str, **ctx) -> Signal:
    return Signal(rule_id=rule_id, detail=f"{rule_id} detail", context=ctx)


@pytest.fixture
def ruleset():
    return load_rules()


def test_no_signals_is_safe(ruleset) -> None:
    result = evaluate([], ruleset)
    assert (result.score, result.verdict) == (0, Verdict.SAFE)


def test_weights_sum_and_thresholds(ruleset) -> None:
    low = evaluate([sig("urgency_language", example="act now")], ruleset)
    assert low.verdict == Verdict.SAFE and low.score == 6
    mid = evaluate([sig("link_text_mismatch", shown="a.com", actual="b.com")], ruleset)
    assert mid.verdict == Verdict.SUSPICIOUS and mid.score == 30
    high = evaluate([sig("dmarc_fail", domain="x.com"), sig("spf_fail"), sig("dkim_fail")], ruleset)
    assert high.verdict == Verdict.PHISHING and high.score == 70


def test_each_rule_counts_once_but_keeps_all_details(ruleset) -> None:
    result = evaluate([sig("link_text_mismatch"), sig("link_text_mismatch")], ruleset)
    assert result.score == 30
    assert result.fired_rules[0].count == 2 and len(result.fired_rules[0].details) == 2


def test_score_is_capped_at_100(ruleset) -> None:
    ids = ["dmarc_fail", "attachment_double_extension", "attachment_executable", "lookalike_domain"]
    assert evaluate([sig(i) for i in ids], ruleset).score <= 100


def test_reasons_sorted_by_weight_and_templated(ruleset) -> None:
    result = evaluate(
        [sig("urgency_language", example="act now"), sig("dmarc_fail", domain="bank.com")], ruleset
    )
    assert [r.rule_id for r in result.reasons][:2] == ["dmarc_fail", "urgency_language"]
    assert "bank.com" in result.reasons[0].text
    assert "act now" in result.reasons[1].text


def test_missing_template_key_does_not_crash(ruleset) -> None:
    result = evaluate([sig("dmarc_fail")], ruleset)
    assert "unknown" in result.reasons[0].text


def test_override_known_malware(ruleset) -> None:
    result = evaluate([sig("vt_file_malicious", filename="x.exe", engines=60)], ruleset)
    assert result.verdict == Verdict.PHISHING
    assert "known_malware_hash" in result.overrides_applied
    assert result.reasons[0].rule_id == "override:known_malware_hash"


def test_override_dmarc_fail_plus_lookalike(ruleset) -> None:
    # dmarc_fail alone is SUSPICIOUS, lookalike alone is already PHISHING by score (45); use
    # a raised phishing threshold to prove the override, not the sum, forces the verdict.
    strict = load_rules("", None, 99)
    result = evaluate([sig("dmarc_fail"), sig("lookalike_domain", brand="paypal")], strict)
    assert result.verdict == Verdict.PHISHING
    assert result.score >= 99
    assert "dmarc_fail_with_lookalike" in result.overrides_applied
    partial = evaluate([sig("lookalike_domain")], strict)
    assert partial.verdict == Verdict.SUSPICIOUS and not partial.overrides_applied


def test_unknown_signal_ignored(ruleset) -> None:
    assert evaluate([sig("not_a_rule")], ruleset).score == 0


def test_configurable_thresholds() -> None:
    custom = load_rules("", 10, 20)
    assert evaluate([sig("urgency_language")], custom).verdict == Verdict.SAFE
    assert (
        evaluate([sig("credential_request_language"), sig("urgency_language")], custom).verdict
        == Verdict.SUSPICIOUS
    )


def test_rules_file_is_well_formed() -> None:
    data = yaml.safe_load(DEFAULT_RULES_PATH.read_text("utf-8"))
    ids = [r["id"] for r in data["rules"]]
    assert len(ids) == len(set(ids))
    for rule in data["rules"]:
        assert {"id", "category", "weight", "description", "explanation"} <= rule.keys()
        assert 0 <= rule["weight"] <= 100
