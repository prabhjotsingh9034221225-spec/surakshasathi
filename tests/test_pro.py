import tempfile
import time
from pathlib import Path

from app import storage


def _fresh():
    storage.init(Path(tempfile.mkdtemp()) / "t.db")


def test_feedback_summary_counts():
    _fresh()
    assert storage.feedback_summary() == {"total": 0, "helpful": 0}
    storage.add_feedback("scam", True)
    storage.add_feedback("safe", False)
    storage.add_feedback("scam", True)
    assert storage.feedback_summary() == {"total": 3, "helpful": 2}


def test_export_is_redacted_and_windowed():
    _fresh()
    storage.add_report(district="Ludhiana", verdict="scam", score=90, category="kyc",
                       snippet="Call 9876543210 or pay to ravi@okhdfc, OTP 482913", channel="web")
    storage.add_report(district="Delhi", verdict="scam", score=80, category="lottery", snippet="old", channel="web", ts=time.time() - 40 * 86400)
    rows = storage.export_reports(30)
    assert len(rows) == 1 and rows[0]["district"] == "Ludhiana"
    blob = str(rows[0])
    assert "9876543210" not in blob and "ravi@okhdfc" not in blob and "482913" not in blob
    assert rows[0]["time_utc"].endswith("Z")


def test_identifier_lookup_counts_reports_by_hash():
    from app import indicators
    _fresh()
    for _ in range(3):
        storage.add_report(district="Ludhiana", verdict="scam", score=90, category="kyc",
                           snippet="Pay to ravi.kumar@okhdfc now", channel="web")
    d = indicators.extract("ravi.kumar@okhdfc")[0]["digest"]
    hit = storage.lookup_indicator(d)
    assert hit["reports"] == 3 and hit["districts"] == ["Ludhiana"] and hit["categories"] == ["kyc"]
    other = storage.lookup_indicator(indicators.extract("someone.else@okhdfc")[0]["digest"])
    assert other["reports"] == 0 and other["last_seen_days"] is None
