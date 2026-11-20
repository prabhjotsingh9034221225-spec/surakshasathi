"""Red-team benchmark: mutate known scam messages the way attackers do and measure the detector.

Runs the offline rule engine (no LLM, no network) so the numbers are reproducible. Cached after the first run.
"""
from __future__ import annotations

import importlib.util
import re
import time
from typing import Any

from .analyzer import analyze
from .config import ROOT

_CACHE: dict[str, Any] = {}


def _load_samples():
    path = ROOT / "tests" / "samples.py"
    spec = importlib.util.spec_from_file_location("surakshasathi_samples", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _leet(t: str) -> str:
    return t.translate(str.maketrans({"o": "0", "O": "0", "i": "1", "a": "@", "e": "3"}))


def _zwsp(t: str) -> str:  # zero-width spaces inside long words
    return re.sub(r"([A-Za-z]{5,})", lambda m: m.group(1)[:2] + "​" + m.group(1)[2:], t)


def _spaced_caps(t: str) -> str:
    return re.sub(r"\b(OTP|PIN|KYC|UPI)\b", lambda m: " ".join(m.group(1)), t, flags=re.I)


def _dotted(t: str) -> str:
    return re.sub(r"\b(otp|pin|kyc|upi)\b", lambda m: ".".join(m.group(1)), t, flags=re.I)


MUTATIONS = {
    "ALL CAPS": lambda t: t.upper(),
    "Emoji padding": lambda t: "🚨🚨 " + t + " 🙏🙏",
    "Polite wrapper": lambda t: "Namaste ji, important notice.\n" + t + "\nRegards, Customer Care Team",
    "Extra punctuation": lambda t: re.sub(r"\.", "!!!", t) + "!!!",
    "Leetspeak (0TP)": _leet,
    "Spaced letters (O T P)": _spaced_caps,
    "Dotted letters (O.T.P)": _dotted,
    "Hidden zero-width chars": _zwsp,
}


def _script(t: str) -> str:
    # Gurmukhi first: Punjabi sentences end with the Devanagari danda, which would look like Hindi.
    if re.search("[\u0a00-\u0a7f]", t):
        return "Punjabi (Gurmukhi)"
    if re.search("[\u0900-\u097f]", t):
        return "Hindi (Devanagari)"
    return "English / Hinglish"


def _flag(text: str) -> bool:
    return analyze(text, None, online=False, use_llm=False).verdict == "scam"


def run(force: bool = False) -> dict[str, Any]:
    if _CACHE and not force:
        return _CACHE
    try:
        S = _load_samples()
    except Exception as exc:  # pragma: no cover
        return {"available": False, "error": f"samples not found: {exc}"}
    scams = [t for n in ("SCAMS", "SCAMS_V2", "SCAMS_V3", "SCAMS_V4", "SCAMS_V5", "SCAMS_V6") for t in getattr(S, n, [])]
    safe = [t for n in ("SAFE", "SAFE_V2", "SAFE_V3", "SAFE_V4", "SAFE_V5", "SAFE_V6") for t in getattr(S, n, [])]
    base = sum(_flag(t) for t in scams)
    safe_fp = sum(_flag(t) for t in safe)
    by_mut, misses = [], []
    lang_tot: dict[str, list[int]] = {}
    total = caught = 0
    for name, fn in MUTATIONS.items():
        ok = 0
        for t in scams:
            m = fn(t)
            hit = _flag(m)
            ok += hit
            lg = _script(t)
            lang_tot.setdefault(lg, [0, 0])
            lang_tot[lg][0] += 1
            lang_tot[lg][1] += hit
            if not hit and len(misses) < 6:
                misses.append({"mutation": name, "text": m[:110]})
        fp = sum(_flag(fn(t)) for t in safe)
        by_mut.append({"mutation": name, "recall": round(ok / len(scams) * 100), "safe_false_alarms": fp, "of_safe": len(safe)})
        total += len(scams)
        caught += ok
    by_lang = [{"language": k, "tested": v[0], "recall": round(v[1] / v[0] * 100)} for k, v in lang_tot.items()]
    # Languages of the unmutated set, for context.
    base_lang: dict[str, list[int]] = {}
    for t in scams:
        k = _script(t)
        base_lang.setdefault(k, [0, 0])
        base_lang[k][0] += 1
        base_lang[k][1] += _flag(t)
    _CACHE.clear()
    _CACHE.update({
        "available": True, "generated_at": time.time(), "engine": "rules only (offline, no LLM)",
        "scams": len(scams), "safe": len(safe),
        "baseline_recall": round(base / len(scams) * 100), "baseline_false_alarms": safe_fp,
        "mutated_cases": total, "mutated_recall": round(caught / total * 100),
        "by_mutation": sorted(by_mut, key=lambda x: x["recall"]),
        "by_language": sorted(by_lang, key=lambda x: x["recall"]),
        "baseline_by_language": [{"language": k, "tested": v[0], "recall": round(v[1] / v[0] * 100)} for k, v in base_lang.items()],
        "misses": misses,
        "note": "Scores are on the project's own labelled messages, which the rules were tuned on, so they are a regression check and overstate real-world accuracy. On brand-new messages written after tuning, the offline rules caught roughly 80% as scam; the AI fallback and link checks add more. Mutations imitate attacker tricks.",
    })
    return _CACHE
