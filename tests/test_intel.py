import tempfile
from pathlib import Path

from app import benchmark, calls, demo, intel, storage


def _seeded():
    storage.init(Path(tempfile.mkdtemp()) / "t.db")
    demo.seed_reports()


def test_outbreak_and_rings_detected():
    _seeded()
    o = intel.outbreaks()
    assert any(a["district"] == "Ludhiana" and a["category"] == "electricity" for a in o["alerts"])
    r = intel.rings()
    assert any(g["label"].startswith("Electricity") and g["identifiers"] >= 3 for g in r["rings"])


def test_feed_is_k_anonymous():
    _seeded()
    f = intel.feed()
    assert all(i["reports"] >= f["k_anonymity"] for i in f["items"])


def test_call_script_flagged_and_normal_call_safe():
    a, sig = calls.analyze_call("I am calling from CBI. Do not disconnect the call, do not tell anyone. Transfer to the RBI verification account.", "en")
    assert a.verdict == "scam" and len(sig) >= 3
    b, _ = calls.analyze_call("Hello, your cheque book is ready, collect it this week.", "en")
    assert b.verdict == "safe"


def test_zero_width_characters_do_not_bypass_rules():
    from app.analyzer import analyze
    assert analyze("Plea​se sh​are the O​TP you recei​ved", "en", online=False, use_llm=False).verdict == "scam"


def test_benchmark_runs():
    r = benchmark.run(True)
    assert r["available"] and r["baseline_recall"] >= 95
