"""SQLite storage. Reports are anonymous: no phone number or full message is kept in them."""
from __future__ import annotations

import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

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
        return int(cur.lastrowid)


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
        c.executescript("DELETE FROM reports; DELETE FROM users; DELETE FROM seen_messages;")


def delete_user(phone: str) -> None:
    """Erase a user's profile (guardian link, district, last flagged message). Anonymous report rows stay."""
    with connect() as c:
        c.execute("DELETE FROM users WHERE phone=?", (phone,))


def clear_guardian(guardian_phone: str) -> int:
    with connect() as c:
        cur = c.execute("UPDATE users SET guardian_phone=NULL WHERE guardian_phone=?", (guardian_phone,))
        return cur.rowcount
