"""Scam analysis pipeline: rules + link checker (+ optional LLM) -> one verdict."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import i18n, llm, rules
from .config import settings
from .links import LinkFinding, check_links

HARD_CATEGORIES = {"pin", "remote_access", "malware", "upi_collect", "extortion"}


@dataclass
class Analysis:
    verdict: str  # safe | suspicious | scam
    score: int
    lang: str
    reason: str
    categories: list[str] = field(default_factory=list)
    links: list[LinkFinding] = field(default_factory=list)
    used_llm: bool = False
    signals: list[str] = field(default_factory=list)

    @property
    def is_high_risk(self) -> bool:
        return self.verdict == "scam"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "language": self.lang,
            "reason": self.reason,
            "categories": self.categories,
            "signals": self.signals,
            "used_llm": self.used_llm,
            "links": [
                {
                    "url": link.url,
                    "host": link.host,
                    "score": link.score,
                    "reasons": link.reasons,
                    "safe_browsing_flagged": link.safe_browsing_flagged,
                    "domain_age_days": link.domain_age_days,
                }
                for link in self.links
            ],
        }


def verdict_for(score: int) -> str:
    if score >= settings.scam_threshold:
        return "scam"
    if score >= settings.suspicious_threshold:
        return "suspicious"
    return "safe"


def analyze(text: str, lang: str | None = None, *, online: bool = True, use_llm: bool = True) -> Analysis:
    lang = lang or i18n.detect_language(text)
    rule_result = rules.evaluate(text)
    links = check_links(text, online=online)
    top_link = max((link.score for link in links), default=0)

    score = rule_result.score
    categories = list(rule_result.categories)
    signals = [h.rule_id for h in rule_result.hits]

    # Fold link evidence in.
    if top_link >= 60:
        score = max(score, 70)
        categories.append("link_link")
        signals.append("dangerous_link")
    elif top_link >= 30:
        score += 25
        categories.append("link_link")
        signals.append("suspicious_link")
    # A link alone, with no other warning sign, is not an alarm; a link plus a warning sign is.
    if links and rule_result.score >= 15 and top_link >= 15:
        score += 10

    score = min(100, score)

    # Optional LLM second opinion for ambiguous cases.
    used_llm = False
    llm_verdict = None
    borderline = 10 <= score < 75 or (links and score < 60) or (score == 0 and len(text.split()) >= 12)
    if use_llm and online and borderline and settings.anthropic_api_key:
        hints = ", ".join(sorted(set(categories))) or "none"
        llm_verdict = llm.classify(text, lang, hints)
        if llm_verdict:
            used_llm = True
            if llm_verdict.verdict == "scam":
                score = max(score, max(llm_verdict.risk, settings.scam_threshold))
            elif llm_verdict.verdict == "suspicious":
                score = max(score, settings.suspicious_threshold)
                if not (set(categories) & HARD_CATEGORIES):
                    score = min(score, settings.scam_threshold - 1)
            elif llm_verdict.verdict == "safe" and not (set(categories) & HARD_CATEGORIES) and top_link < 60:
                score = min(score, settings.suspicious_threshold - 5)
            signals.append(f"llm:{llm_verdict.verdict}")

    verdict = verdict_for(score)

    if verdict == "safe":
        reason = i18n.REASONS["protective" if rule_result.protective else "safe"][lang]
    elif llm_verdict and llm_verdict.reason and llm_verdict.verdict == verdict:
        reason = llm_verdict.reason
    else:
        reason = i18n.reason_for(categories, lang, link_flagged="link_link" in categories)

    return Analysis(
        verdict=verdict,
        score=score,
        lang=lang,
        reason=reason,
        categories=sorted(set(categories)),
        links=links,
        used_llm=used_llm,
        signals=signals,
    )
