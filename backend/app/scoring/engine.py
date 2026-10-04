"""Rule-based scoring engine.

Analysis modules emit :class:`~app.models.Signal` objects; this engine looks up each signal's
weight and plain-English template in ``rules.yaml``, sums the weights, and maps the total to a
verdict. Keeping the numbers in YAML (not code) lets an analyst re-tune detection without
touching Python and makes every point of the score traceable to a named rule.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.models import FiredRule, Reason, Signal, Verdict

log = logging.getLogger(__name__)
DEFAULT_RULES_PATH = Path(__file__).parent / "rules.yaml"
MAX_REASONS = 5


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: int
    description: str
    explanation: str


@dataclass(frozen=True)
class Override:
    id: str
    requires_all: tuple[str, ...]
    verdict: Verdict
    explanation: str


@dataclass
class RuleSet:
    rules: dict[str, Rule]
    overrides: list[Override]
    suspicious_threshold: int
    phishing_threshold: int


@dataclass
class ScoringResult:
    score: int
    verdict: Verdict
    reasons: list[Reason] = field(default_factory=list)
    fired_rules: list[FiredRule] = field(default_factory=list)
    overrides_applied: list[str] = field(default_factory=list)


class _SafeDict(dict):
    """format_map helper: a missing key renders as 'unknown' instead of raising."""

    def __missing__(self, key: str) -> str:
        return "unknown"


@lru_cache(maxsize=4)
def load_rules(
    path: str = "",
    suspicious: int | None = None,
    phishing: int | None = None,
) -> RuleSet:
    """Load and validate a rules file. ``suspicious``/``phishing`` override the YAML thresholds."""
    data: dict[str, Any] = yaml.safe_load(Path(path or DEFAULT_RULES_PATH).read_text("utf-8"))
    rules = {r["id"]: Rule(**{k: r[k] for k in Rule.__dataclass_fields__}) for r in data["rules"]}
    if len(rules) != len(data["rules"]):
        raise ValueError("Duplicate rule ids in rules file")
    overrides = []
    for o in data.get("overrides", []):
        missing = [rid for rid in o["requires_all"] if rid not in rules]
        if missing:
            raise ValueError(f"Override {o['id']} references unknown rules: {missing}")
        overrides.append(
            Override(o["id"], tuple(o["requires_all"]), Verdict(o["verdict"]), o["explanation"])
        )
    thresholds = data["thresholds"]
    return RuleSet(
        rules=rules,
        overrides=overrides,
        suspicious_threshold=suspicious if suspicious is not None else thresholds["suspicious"],
        phishing_threshold=phishing if phishing is not None else thresholds["phishing"],
    )


def evaluate(signals: list[Signal], ruleset: RuleSet) -> ScoringResult:
    """Score a list of signals."""
    grouped: dict[str, list[Signal]] = defaultdict(list)
    for sig in signals:
        if sig.rule_id in ruleset.rules:
            grouped[sig.rule_id].append(sig)
        else:
            log.warning("signal for unknown rule %s ignored", sig.rule_id)

    fired: list[FiredRule] = []
    reasons: list[Reason] = []
    for rule_id, sigs in grouped.items():
        rule = ruleset.rules[rule_id]
        context = dict(sigs[0].context)
        context.setdefault("count", len(sigs))
        fired.append(
            FiredRule(
                rule_id=rule.id,
                category=rule.category,
                weight=rule.weight,
                description=rule.description,
                count=len(sigs),
                details=[s.detail for s in sigs],
            )
        )
        if rule.weight > 0:
            reasons.append(
                Reason(
                    rule_id=rule.id,
                    weight=rule.weight,
                    text=rule.explanation.format_map(_SafeDict(context)),
                )
            )
    fired.sort(key=lambda r: (-r.weight, r.rule_id))
    reasons.sort(key=lambda r: (-r.weight, r.rule_id))

    # Each rule counts once: ten mismatched links are not ten times as suspicious as one, and
    # this keeps the score explainable ("this rule contributed N points").
    score = min(100, sum(r.weight for r in fired))
    if score >= ruleset.phishing_threshold:
        verdict = Verdict.PHISHING
    elif score >= ruleset.suspicious_threshold:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.SAFE

    fired_ids = {r.rule_id for r in fired}
    applied: list[str] = []
    for ov in ruleset.overrides:
        if all(rid in fired_ids for rid in ov.requires_all):
            applied.append(ov.id)
            reasons.insert(0, Reason(rule_id=f"override:{ov.id}", weight=100, text=ov.explanation))
            if _rank(ov.verdict) > _rank(verdict):
                verdict = ov.verdict
                # keep score and verdict consistent when an override raises the verdict
                floor = (
                    ruleset.phishing_threshold
                    if verdict == Verdict.PHISHING
                    else ruleset.suspicious_threshold
                )
                score = max(score, floor)
    return ScoringResult(
        score=score,
        verdict=verdict,
        reasons=reasons[:MAX_REASONS],
        fired_rules=fired,
        overrides_applied=applied,
    )


def _rank(verdict: Verdict) -> int:
    return {Verdict.SAFE: 0, Verdict.SUSPICIOUS: 1, Verdict.PHISHING: 2}[verdict]
