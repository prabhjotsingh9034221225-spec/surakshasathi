"""Call-script scoring: finds the pressure patterns used in scam phone calls inside a transcript.

Works on a transcript (pasted, or produced by app.speech.transcribe from an uploaded recording).
"""
from __future__ import annotations

import re

from . import explain
from .analyzer import Analysis, analyze, verdict_for
from .rules import normalise

# (signal id, category used for explanations, weight, patterns)
SIGNALS = (
    ("isolation", "isolation", 25, (
        r"\b(?:do not|don't|dont|never) (?:tell|inform|share this with|speak to|talk to) (?:anyone|anybody|your family|family|your wife|your husband|your son|your daughter|friends?|bank)",
        r"\b(?:keep|maintain) (?:this|it) (?:a )?(?:secret|confidential)",
        r"\bkisi ko (?:mat|na) (?:batana|batao|bataiye)",
        r"(?:किसी को (?:न|मत) बता|परिवार को (?:न|मत) बता|गोपनीय रखें)",
        r"(?:ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸ|ਪਰਿਵਾਰ ਨੂੰ ਨਾ ਦੱਸ)",
    )),
    ("stay_on_line", "stay_on_line", 30, (
        r"\b(?:do not|don't|dont|never) (?:disconnect|cut|hang up|end) (?:the |this )?(?:call|line|video)",
        r"\bstay on (?:the )?(?:call|line|video call)\b",
        r"\bkeep (?:the )?(?:video )?call (?:on|connected)\b",
        r"\b(?:call|phone) (?:mat|na) kat(?:na|o|iye)",
        r"(?:कॉल (?:मत|न) काट|फोन (?:मत|न) काट|वीडियो कॉल पर रहें)",
        r"(?:ਕਾਲ ਨਾ ਕੱਟ|ਫ਼ੋਨ ਨਾ ਕੱਟ)",
    )),
    ("safe_account", "safe_account", 50, (
        r"\b(?:safe|secure|verification|rbi|government|escrow) account\b",
        r"\btransfer (?:the )?(?:money|amount|funds?|balance).{0,60}(?:verify|verification|rbi|safe|investigation|clearance)",
        r"\brefundable (?:deposit|amount)\b",
        r"(?:सुरक्षित खाते|आरबीआई खाते|वेरिफिकेशन खाते)",
        r"(?:ਸੁਰੱਖਿਅਤ ਖਾਤੇ|ਆਰਬੀਆਈ ਖਾਤੇ)",
    )),
    ("authority_call", "authority_call", 30, (
        r"\b(?:this is|calling from|i am|i'm|speaking from).{0,40}(?:cbi|police|crime branch|narcotics|customs|trai|enforcement directorate|cyber ?cell|rbi)\b",
        r"\byour (?:aadhaar|aadhar|sim|mobile number|number|parcel|courier|account) (?:is|has been|was) (?:linked|involved|used|found|connected).{0,60}(?:money laundering|crime|illegal|drugs|fraud|case)",
        r"(?:सीबीआई|पुलिस|नारकोटिक्स|ट्राई|कस्टम).{0,40}(?:से बोल|की तरफ से|अधिकारी)",
    )),
    ("sim_threat", "sim_threat", 25, (
        r"\byour (?:sim|mobile number|number|connection) (?:will be|is going to be) (?:blocked|disconnected|deactivated|suspended)",
        r"(?:सिम|नंबर).{0,20}(?:बंद|ब्लॉक) (?:हो जाएगा|कर दिया जाएगा)",
        r"(?:ਸਿਮ|ਨੰਬਰ).{0,20}(?:ਬੰਦ|ਬਲੌਕ) ਹੋ ਜਾਵੇਗਾ",
    )),
)
_COMPILED = tuple((sid, cat, w, tuple(re.compile(p, re.I) for p in pats)) for sid, cat, w, pats in SIGNALS)


def call_signals(transcript: str) -> list[dict]:
    norm = normalise(transcript)
    out = []
    for sid, cat, weight, pats in _COMPILED:
        for p in pats:
            m = p.search(norm)
            if m:
                out.append({"id": sid, "category": cat, "weight": weight, "matched": m.group(0)[:80]})
                break
    return out


def analyze_call(transcript: str, lang: str | None = None) -> tuple[Analysis, list[dict]]:
    a = analyze(transcript, lang, online=False)
    sig = call_signals(transcript)
    score = a.score + sum(s["weight"] for s in sig)
    if len(sig) >= 2:
        score += 15  # two or more call-pressure tactics together are a strong script signature
    a.score = min(100, score)
    a.verdict = verdict_for(a.score)
    a.categories = sorted(set(a.categories) | {s["category"] for s in sig})
    a.signals = list(a.signals) + [s["id"] for s in sig]
    if sig and a.verdict != "safe":
        top = max(sig, key=lambda s: s["weight"])
        a.reason = explain.WHY[top["category"]].get(a.lang) or explain.WHY[top["category"]]["en"]
    return a, sig
