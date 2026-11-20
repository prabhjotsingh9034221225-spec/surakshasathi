"""SQLite storage. Reports are anonymous: no phone number or full message is kept in them."""
from __future__ import annotations

import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import indicators
from .config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    phone TEXT PRIMARY KEY,
    lang TEXT NOT NULL DEFAULT 'en',
    district TEXT,
    guardian_phone TEXT,
    created_at REAL NOT NULL,
    last_alert_at REAL,
    last_scam_text TEXT,
    last_scam_category TEXT,
    last_scam_at REAL
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    district TEXT,
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    category TEXT NOT NULL,
    snippet TEXT,
    channel TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(ts);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    hint TEXT,
    district TEXT
);
CREATE INDEX IF NOT EXISTS idx_ind_digest ON indicators(digest);
CREATE INDEX IF NOT EXISTS idx_ind_report ON indicators(report_id);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    verdict TEXT,
    helpful INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_subs (
    phone TEXT PRIMARY KEY,
    district TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts_sent (
    day TEXT NOT NULL,
    district TEXT NOT NULL,
    category TEXT NOT NULL,
    PRIMARY KEY (day, district, category)
);
CREATE TABLE IF NOT EXISTS seen_messages (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL
);
"""

_lock = threading.RLock()
_db_path: Path | None = None


def init(path: Path | None = None) -> None:
    global _db_path
    _db_path = Path(path or settings.database_path)
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(_SCHEMA)


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    if _db_path is None:
        init()
    conn = sqlite3.connect(_db_path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        with _lock:
            yield conn
            conn.commit()
    finally:
        conn.close()


def redact(text: str, limit: int = 140) -> str:
    """Remove phone numbers, long digit runs (OTP, card, account) and UPI IDs from a snippet."""
    text = re.sub(r"[\w.\-]{2,}@[a-z]{2,}", "[upi]", text or "", flags=re.I)
    text = re.sub(r"\+?\d[\d\s\-]{5,}\d", "[number]", text)
    text = re.sub(r"\b\d{4,}\b", "[number]", text)  # bare OTPs / PINs / amounts of 4+ digits
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


# ---- users ---------------------------------------------------------------
def get_user(phone: str) -> dict[str, Any] | None:
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        return dict(row) if row else None


def ensure_user(phone: str, lang: str = "en") -> tuple[dict[str, Any], bool]:
    """Return (user, created)."""
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        if row:
            return dict(row), False
        c.execute("INSERT INTO users(phone, lang, created_at) VALUES (?,?,?)", (phone, lang, time.time()))
        row = c.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        return dict(row), True


def update_user(phone: str, **fields: Any) -> None:
    allowed = {"lang", "district", "guardian_phone", "last_alert_at", "last_scam_text", "last_scam_category", "last_scam_at"}
    cols = [k for k in fields if k in allowed]
    if not cols:
        return
    sets = ", ".join(f"{k}=?" for k in cols)
    with connect() as c:
        c.execute(f"UPDATE users SET {sets} WHERE phone=?", [fields[k] for k in cols] + [phone])


def users_guarded_by(guardian_phone: str) -> list[dict[str, Any]]:
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM users WHERE guardian_phone=?", (guardian_phone,))]


def all_users() -> list[dict[str, Any]]:
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM users")]


# ---- reports -------------------------------------------------------------
def add_report(*, district: str | None, verdict: str, score: int, category: str, snippet: str, channel: str, ts: float | None = None) -> int:
    with connect() as c:
        cur = c.execute(
            "INSERT INTO reports(ts, district, verdict, score, category, snippet, channel) VALUES (?,?,?,?,?,?,?)",
            (ts or time.time(), district, verdict, score, category, redact(snippet), channel),
        )
        rid = int(cur.lastrowid)
        if verdict != "safe":
            for ind in indicators.extract(snippet):
                c.execute(
                    "INSERT INTO indicators(report_id, ts, kind, digest, hint, district) VALUES (?,?,?,?,?,?)",
                    (rid, ts or time.time(), ind["kind"], ind["digest"], ind["hint"], district),
                )
        return rid


def stats(since_days: int = 30) -> dict[str, Any]:
    cutoff = time.time() - since_days * 86400
    with connect() as c:
        total = c.execute("SELECT COUNT(*) FROM reports WHERE ts>=?", (cutoff,)).fetchone()[0]
        by_verdict = {r["verdict"]: r["n"] for r in c.execute("SELECT verdict, COUNT(*) n FROM reports WHERE ts>=? GROUP BY verdict", (cutoff,))}
        by_category = [
            {"category": r["category"], "count": r["n"]}
            for r in c.execute("SELECT category, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' GROUP BY category ORDER BY n DESC LIMIT 8", (cutoff,))
        ]
        users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        guarded = c.execute("SELECT COUNT(*) FROM users WHERE guardian_phone IS NOT NULL").fetchone()[0]
        daily = [
            {"day": r["d"], "count": r["n"]}
            for r in c.execute(
                "SELECT date(ts,'unixepoch','localtime') d, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' GROUP BY d ORDER BY d", (cutoff,)
            )
        ]
    return {
        "total_checked": total,
        "scams_blocked": by_verdict.get("scam", 0),
        "suspicious": by_verdict.get("suspicious", 0),
        "safe": by_verdict.get("safe", 0),
        "users": users,
        "users_with_guardian": guarded,
        "by_category": by_category,
        "daily": daily,
    }


def heatmap(since_days: int = 30) -> list[dict[str, Any]]:
    cutoff = time.time() - since_days * 86400
    with connect() as c:
        rows = c.execute(
            "SELECT district, COUNT(*) n, MAX(ts) last_ts FROM reports WHERE ts>=? AND verdict!='safe' AND district IS NOT NULL GROUP BY district",
            (cutoff,),
        ).fetchall()
        out = []
        for r in rows:
            top = c.execute(
                "SELECT category, COUNT(*) n FROM reports WHERE ts>=? AND district=? AND verdict!='safe' GROUP BY category ORDER BY n DESC LIMIT 1",
                (cutoff, r["district"]),
            ).fetchone()
            out.append({"district": r["district"], "count": r["n"], "last_ts": r["last_ts"], "top_category": top["category"] if top else None})
        return out


def recent_reports(limit: int = 15) -> list[dict[str, Any]]:
    with connect() as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT id, ts, district, verdict, score, category, snippet, channel FROM reports WHERE verdict!='safe' ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        ]


# ---- webhook dedupe --------------------------------------------------------
def first_time_seen(message_id: str) -> bool:
    """True the first time a webhook message id is seen (providers retry deliveries)."""
    with connect() as c:
        try:
            c.execute("INSERT INTO seen_messages(id, ts) VALUES (?,?)", (message_id, time.time()))
            c.execute("DELETE FROM seen_messages WHERE ts<?", (time.time() - 86400,))
            return True
        except sqlite3.IntegrityError:
            return False


def clear_all() -> None:
    with connect() as c:
        c.executescript("DELETE FROM reports; DELETE FROM indicators; DELETE FROM users; DELETE FROM seen_messages;")


def delete_user(phone: str) -> None:
    """Erase a user's profile (guardian link, district, last flagged message). Anonymous report rows stay."""
    with connect() as c:
        c.execute("DELETE FROM users WHERE phone=?", (phone,))
        c.execute("DELETE FROM alert_subs WHERE phone=?", (phone,))


def clear_guardian(guardian_phone: str) -> int:
    with connect() as c:
        cur = c.execute("UPDATE users SET guardian_phone=NULL WHERE guardian_phone=?", (guardian_phone,))
        return cur.rowcount


def add_feedback(verdict: str | None, helpful: bool) -> None:
    """Anonymous thumbs up/down on a verdict. No text, phone or message content is stored."""
    with connect() as c:
        c.execute("INSERT INTO feedback(ts, verdict, helpful) VALUES (?,?,?)", (time.time(), verdict, 1 if helpful else 0))


def feedback_summary() -> dict[str, int]:
    with connect() as c:
        row = c.execute("SELECT COUNT(*), COALESCE(SUM(helpful),0) FROM feedback").fetchone()
    return {"total": row[0], "helpful": row[1]}


def export_reports(days: int = 30, limit: int = 20000) -> list[dict[str, Any]]:
    """Anonymous report rows for authorised analysts (police, banks, CERT-In). Snippets are already redacted."""
    cutoff = time.time() - days * 86400
    with connect() as c:
        rows = c.execute(
            "SELECT id, ts, district, verdict, score, category, channel, snippet FROM reports WHERE ts>=? ORDER BY ts DESC LIMIT ?",
            (cutoff, limit),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["time_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(d.pop("ts")))
        out.append(d)
    return out


def lookup_indicator(digest: str, days: int = 90) -> dict[str, Any]:
    """How often a phone number / UPI ID / domain (by salted hash) appears in non-safe reports. Counts only."""
    cutoff = time.time() - days * 86400
    with connect() as c:
        rows = c.execute(
            "SELECT i.ts, i.district, r.category FROM indicators i JOIN reports r ON r.id = i.report_id WHERE i.digest=? AND i.ts>=?",
            (digest, cutoff),
        ).fetchall()
    cats: dict[str, int] = {}
    for r in rows:
        if r["category"]:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
    return {
        "reports": len(rows),
        "districts": sorted({r["district"] for r in rows if r["district"]}),
        "last_seen_days": int((time.time() - max(r["ts"] for r in rows)) // 86400) if rows else None,
        "categories": sorted(cats, key=cats.get, reverse=True)[:3],
    }


# ---- district alerts -----------------------------------------------------
def alert_subscribe(phone: str, district: str) -> None:
    with connect() as c:
        c.execute("INSERT OR REPLACE INTO alert_subs(phone, district, created_at) VALUES (?,?,?)", (phone, district, time.time()))


def alert_unsubscribe(phone: str) -> bool:
    with connect() as c:
        return c.execute("DELETE FROM alert_subs WHERE phone=?", (phone,)).rowcount > 0


def alert_subscribers(district: str) -> list[dict[str, Any]]:
    with connect() as c:
        rows = c.execute(
            "SELECT a.phone, COALESCE(u.lang,'en') lang FROM alert_subs a LEFT JOIN users u ON u.phone=a.phone WHERE a.district=?",
            (district,),
        ).fetchall()
    return [dict(r) for r in rows]


def alert_subscribers_all() -> list[dict[str, Any]]:
    with connect() as c:
        rows = c.execute("SELECT a.phone, COALESCE(u.lang,'en') lang FROM alert_subs a LEFT JOIN users u ON u.phone=a.phone").fetchall()
    return [dict(r) for r in rows]


def alert_subscriber_count() -> int:
    with connect() as c:
        return int(c.execute("SELECT COUNT(*) FROM alert_subs").fetchone()[0])


def alert_already_sent(day: str, district: str, category: str) -> bool:
    with connect() as c:
        return c.execute("SELECT 1 FROM alerts_sent WHERE day=? AND district=? AND category=?", (day, district, category)).fetchone() is not None


def mark_alert_sent(day: str, district: str, category: str) -> None:
    with connect() as c:
        c.execute("INSERT OR IGNORE INTO alerts_sent(day, district, category) VALUES (?,?,?)", (day, district, category))
