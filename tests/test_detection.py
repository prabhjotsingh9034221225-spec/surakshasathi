"""Regression guard for the detector: every labelled message set must stay fully classified,
and attacker disguises (leetspeak, spaced letters, padding ...) must not hide a scam."""
import pytest

from app import benchmark
from app.analyzer import analyze
from tests import samples as S

SETS = ["", "_V2", "_V3", "_V4", "_V5", "_V6"]


def _verdict(text: str) -> str:
    return analyze(text, online=False, use_llm=False).verdict


@pytest.mark.parametrize("suffix", SETS)
def test_every_known_scam_is_flagged_scam(suffix):
    missed = [t for t in getattr(S, "SCAMS" + suffix) if _verdict(t) != "scam"]
    assert not missed, f"{len(missed)} scams not flagged: {missed[:3]}"


@pytest.mark.parametrize("suffix", SETS)
def test_no_genuine_message_is_called_a_scam(suffix):
    wrong = [t for t in getattr(S, "SAFE" + suffix) if _verdict(t) == "scam"]
    assert not wrong, f"false scam alarms: {wrong[:3]}"


def test_ambiguous_messages_are_never_called_safe_without_thought():
    # Scammers use this exact wording, so the app should not wave it through as safe silently.
    assert all(_verdict(t) in {"suspicious", "scam"} for t in S.AMBIGUOUS)


def test_attacker_disguises_do_not_hide_scams():
    r = benchmark.run()
    assert r["baseline_recall"] == 100 and r["baseline_false_alarms"] == 0
    assert r["mutated_recall"] >= 98
