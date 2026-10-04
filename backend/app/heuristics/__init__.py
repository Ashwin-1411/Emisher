"""Heuristic detections: spoofing, lookalike domains, domain age and wording."""

from app.heuristics.analyze import analyze_heuristics
from app.heuristics.domain_age import YOUNG_DOMAIN_DAYS, age_in_days, domain_age_signals
from app.heuristics.lookalike import Lookalike, check_domain

__all__ = [
    "YOUNG_DOMAIN_DAYS",
    "Lookalike",
    "age_in_days",
    "analyze_heuristics",
    "check_domain",
    "domain_age_signals",
]
