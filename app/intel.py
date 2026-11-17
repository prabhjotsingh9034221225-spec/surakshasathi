"""Early-warning intelligence built on the anonymous reports table.

Outbreak detection, campaign clustering, trends + forecast, scammer rings, awareness alerts and a
k-anonymous threat feed. Everything is computed on demand from SQLite (fast at demo/pilot scale).
"""
from __future__ import annotations

import datetime as dt
import re
import time
from collections import Counter, defaultdict
from typing import Any

from . import explain, storage

HOUR = 3600
DAY = 86400
K_ANON = 5

LABELS = {
    "kyc": "Fake KYC / account block", "otp": "OTP theft", "pin": "UPI PIN theft", "upi_collect": "Fake UPI collect / refund",
    "lottery": "Lottery and prize fee", "electricity": "Electricity cut-off", "legal_threat": "Digital arrest / police threat",
    "remote_access": "Remote-access app (AnyDesk)", "job_scam": "Fake job / task", "parcel": "Courier / customs",
    "investment": "Investment fraud", "advance_fee": "Advance-fee fraud", "malware": "Malicious APK", "extortion": "Blackmail",
    "family_impersonation": "Relative impersonation", "wrong_transfer": "'Sent by mistake' refund", "credentials": "Password phishing",
    "block_threat": "Account-block threat", "link_link": "Phishing link", "link_bait": "Phishing link", "urgency": "Pressure tactics",
    "impersonation": "Bank / govt impersonation", "none": "Other",
}


def label(cat: str) -> str:
    return LABELS.get(cat, cat.replace("_", " ").title())


def _rows(sql: str, args: tuple = ()) -> list[dict[str, Any]]:
    with storage.connect() as c:
        return [dict(r) for r in c.execute(sql, args)]


# ------------------------------------------------------------------ outbreaks + campaigns
_WORD = re.compile(r"[a-zऀ-ॿ਀-੿0-9]+", re.I)


def _tokens(text: str) -> frozenset[str]:
    return frozenset(w.lower() for w in _WORD.findall(text or "") if len(w) > 2 and w.lower() not in {"the", "and", "for", "you", "your", "link", "number"})


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def outbreaks(now: float | None = None, window_h: int = 6) -> dict[str, Any]:
    """Districts where a scam category is spiking vs its own 7-day baseline, plus live campaign clusters."""
    now = now or time.time()
    win = window_h * HOUR
    base_windows = 7 * DAY / win
    recent = _rows(
        "SELECT district, category, COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts FROM reports "
        "WHERE ts>=? AND verdict!='safe' AND district IS NOT NULL GROUP BY district, category",
        (now - win,),
    )
    base = {
        (r["district"], r["category"]): r["n"]
        for r in _rows(
            "SELECT district, category, COUNT(*) n FROM reports WHERE ts>=? AND ts<? AND verdict!='safe' AND district IS NOT NULL GROUP BY district, category",
            (now - win - 7 * DAY, now - win),
        )
    }
    alerts = []
    for r in recent:
        expected = max(base.get((r["district"], r["category"]), 0) / base_windows, 0.5)
        ratio = r["n"] / expected
        if r["n"] >= 5 and ratio >= 3:
            level = "critical" if r["n"] >= 12 and ratio >= 8 else "high" if ratio >= 5 else "watch"
            alerts.append({
                "district": r["district"], "category": r["category"], "label": label(r["category"]), "count": r["n"],
                "expected": round(expected, 1), "ratio": round(ratio, 1), "level": level,
                "first_seen": r["first_ts"], "last_seen": r["last_ts"],
            })
    alerts.sort(key=lambda a: (-a["ratio"], -a["count"]))

    # Campaign clusters: near-duplicate wording in the last 24h, grouped greedily by Jaccard similarity.
    msgs = _rows(
        "SELECT ts, district, category, snippet FROM reports WHERE ts>=? AND verdict!='safe' AND snippet IS NOT NULL ORDER BY ts",
        (now - DAY,),
    )
    clusters: list[dict[str, Any]] = []
    for m in msgs:
        tok = _tokens(m["snippet"])
        best, best_sim = None, 0.0
        for cl in clusters:
            sim = _jaccard(tok, cl["tok"])
            if sim > best_sim:
                best, best_sim = cl, sim
        if best is not None and best_sim >= 0.45:
            best["rows"].append(m)
            best["tok"] = best["tok"] | tok
        else:
            clusters.append({"tok": tok, "rows": [m]})
    out_clusters = []
    for cl in clusters:
        rows = cl["rows"]
        if len(rows) < 3:
            continue
        cats = Counter(r["category"] for r in rows)
        dists = Counter(r["district"] for r in rows if r["district"])
        last2h = sum(1 for r in rows if r["ts"] >= now - 2 * HOUR)
        prev2h = sum(1 for r in rows if now - 4 * HOUR <= r["ts"] < now - 2 * HOUR)
        out_clusters.append({
            "size": len(rows), "category": cats.most_common(1)[0][0], "label": label(cats.most_common(1)[0][0]),
            "sample": rows[-1]["snippet"], "districts": [d for d, _ in dists.most_common(4)],
            "first_seen": rows[0]["ts"], "last_seen": rows[-1]["ts"], "last_2h": last2h, "prev_2h": prev2h,
            "trend": "rising" if last2h > prev2h else "falling" if last2h < prev2h else "steady",
        })
    out_clusters.sort(key=lambda c: -c["size"])

    curve = {"category": None, "label": None, "hours": []}
    if alerts:
        top = alerts[0]
        curve["category"], curve["label"] = top["category"], top["label"]
    elif out_clusters:
        curve["category"], curve["label"] = out_clusters[0]["category"], out_clusters[0]["label"]
    if curve["category"]:
        buckets = [0] * 24
        for r in _rows("SELECT ts FROM reports WHERE ts>=? AND category=? AND verdict!='safe'", (now - 24 * HOUR, curve["category"])):
            idx = 23 - int((now - r["ts"]) // HOUR)
            if 0 <= idx < 24:
                buckets[idx] += 1
        curve["hours"] = buckets
    return {"generated_at": now, "window_hours": window_h, "alerts": alerts[:8], "campaigns": out_clusters[:6], "curve": curve}


# ------------------------------------------------------------------ trends + forecast
def _linear(ys: list[float]) -> tuple[float, float]:
    n = len(ys)
    if n < 2:
        return 0.0, (ys[0] if ys else 0.0)
    xs = list(range(n))
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs) or 1
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
    return slope, my - slope * mx


def trends(now: float | None = None) -> dict[str, Any]:
    now = now or time.time()
    today = dt.date.fromtimestamp(now)
    days = 28
    start = today - dt.timedelta(days=days - 1)
    daily_map = {
        r["d"]: r["n"]
        for r in _rows(
            "SELECT date(ts,'unixepoch','localtime') d, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' GROUP BY d",
            (now - days * DAY,),
        )
    }
    series = [{"day": (start + dt.timedelta(days=i)).isoformat(), "count": daily_map.get((start + dt.timedelta(days=i)).isoformat(), 0)} for i in range(days)]
    ys = [float(p["count"]) for p in series[-14:]]
    slope, intercept = _linear(ys)
    forecast = []
    for i in range(1, 8):
        v = max(0.0, intercept + slope * (len(ys) - 1 + i))
        forecast.append({"day": (today + dt.timedelta(days=i)).isoformat(), "count": round(v, 1)})

    # Category movement: last 7 days vs the 7 days before.
    cur = Counter({r["category"]: r["n"] for r in _rows("SELECT category, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' GROUP BY category", (now - 7 * DAY,))})
    prev = Counter({r["category"]: r["n"] for r in _rows("SELECT category, COUNT(*) n FROM reports WHERE ts>=? AND ts<? AND verdict!='safe' GROUP BY category", (now - 14 * DAY, now - 7 * DAY))})
    movers = []
    for cat in set(cur) | set(prev):
        a, b = cur.get(cat, 0), prev.get(cat, 0)
        change = None if b == 0 else round((a - b) / b * 100)
        movers.append({"category": cat, "label": label(cat), "this_week": a, "last_week": b, "change_pct": change, "next_week_expected": max(0, round(a + (a - b) * 0.5))})
    movers.sort(key=lambda m: -m["this_week"])

    monthly_rows = _rows(
        "SELECT strftime('%Y-%m', ts,'unixepoch','localtime') m, category, COUNT(*) n FROM reports WHERE verdict!='safe' GROUP BY m, category ORDER BY m"
    )
    by_month: dict[str, dict[str, int]] = defaultdict(dict)
    for r in monthly_rows:
        by_month[r["m"]][r["category"]] = r["n"]
    monthly = [{"month": m, "total": sum(c.values()), "top": [{"category": k, "label": label(k), "count": v} for k, v in sorted(c.items(), key=lambda kv: -kv[1])[:3]]} for m, c in sorted(by_month.items())][-12:]
    return {
        "daily": series, "forecast": forecast, "movers": movers[:8], "monthly": monthly,
        "method": "Linear trend on the last 14 days (demo-grade). Category outlook = this week plus half the week-on-week change.",
        "seasonal_watch": [
            {"months": "Apr-Jul", "scam": "Electricity cut-off threats"}, {"months": "Month end", "scam": "Fake KYC / salary-account blocks"},
            {"months": "Jul and Mar", "scam": "Income-tax refund and PAN update"}, {"months": "Oct-Nov", "scam": "Festival gift, lottery and delivery scams"},
        ],
    }


# ------------------------------------------------------------------ scammer rings
def rings(min_reports: int = 2) -> dict[str, Any]:
    ind = _rows("SELECT report_id, digest, kind, hint, district, ts FROM indicators")
    if not ind:
        return {"rings": [], "total_identifiers": 0}
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    by_report: dict[int, list[dict]] = defaultdict(list)
    for r in ind:
        by_report[r["report_id"]].append(r)
        find(r["digest"])
    edges: set[tuple[str, str]] = set()
    for items in by_report.values():
        ds = [i["digest"] for i in items]
        for a in ds[1:]:
            union(ds[0], a)
        for i in range(len(ds)):
            for j in range(i + 1, len(ds)):
                if ds[i] != ds[j]:
                    edges.add(tuple(sorted((ds[i], ds[j]))))
    groups: dict[str, list[str]] = defaultdict(list)
    meta: dict[str, dict] = {}
    for r in ind:
        meta.setdefault(r["digest"], {"kind": r["kind"], "hint": r["hint"], "reports": set(), "districts": set(), "first": r["ts"], "last": r["ts"]})
        m = meta[r["digest"]]
        m["reports"].add(r["report_id"])
        if r["district"]:
            m["districts"].add(r["district"])
        m["first"], m["last"] = min(m["first"], r["ts"]), max(m["last"], r["ts"])
    for d in meta:
        groups[find(d)].append(d)
    cats = {r["id"]: r["category"] for r in _rows("SELECT id, category FROM reports")}
    out = []
    for members in groups.values():
        report_ids = set().union(*(meta[d]["reports"] for d in members))
        if len(members) < 2 or len(report_ids) < min_reports:
            continue
        districts = Counter(x for d in members for x in meta[d]["districts"])
        cat_count = Counter(cats.get(rid, "none") for rid in report_ids)
        nodes = sorted(members, key=lambda d: -len(meta[d]["reports"]))
        out.append({
            "identifiers": len(members), "reports": len(report_ids),
            "kinds": dict(Counter(meta[d]["kind"] for d in members)),
            "districts": [d for d, _ in districts.most_common(5)],
            "category": cat_count.most_common(1)[0][0], "label": label(cat_count.most_common(1)[0][0]),
            "first_seen": min(meta[d]["first"] for d in members), "last_seen": max(meta[d]["last"] for d in members),
            "nodes": [{"id": d, "kind": meta[d]["kind"], "hint": meta[d]["hint"], "reports": len(meta[d]["reports"])} for d in nodes[:10]],
            "edges": [{"a": a, "b": b} for a, b in edges if a in members and b in members][:30],
        })
    out.sort(key=lambda g: (-g["reports"], -g["identifiers"]))
    return {"rings": out[:6], "total_identifiers": len(meta)}


# ------------------------------------------------------------------ awareness
PREBUNK = {
    "kyc": ("A text says your bank KYC will expire today and gives a link. What should you do?", ["Click the link and update", "Ignore it and visit your branch"], 1, "Banks never update KYC through SMS or WhatsApp links."),
    "otp": ("A caller from 'the bank' needs the OTP you just got to cancel a payment. Do you share it?", ["Yes, to stop the payment", "No, never share an OTP"], 1, "An OTP is a key to your money. No real bank asks for it."),
    "upi_collect": ("You get a request to 'enter your UPI PIN to receive a refund'. Is this safe?", ["Yes, refunds need a PIN", "No, receiving money needs no PIN"], 1, "A PIN is only for sending money. Decline the request."),
    "lottery": ("You won a lottery you never entered, but must pay a small fee first. Real?", ["Yes, pay the fee", "No, it is a scam"], 1, "Real prizes never ask for a fee in advance."),
    "electricity": ("A message says power will be cut tonight unless you call a number. What now?", ["Call the number quickly", "Check with your electricity office"], 1, "Utilities do not threaten same-night cut-offs by SMS."),
    "legal_threat": ("Someone on a video call says you are under 'digital arrest'. Is that a thing?", ["Yes, I must obey", "No, it does not exist in Indian law"], 1, "There is no digital arrest. Hang up and call 1930 if pressured."),
    "remote_access": ("A 'bank executive' asks you to install AnyDesk to fix your refund. Okay?", ["Yes", "No, it lets them control my phone"], 1, "Screen-sharing apps give strangers full access to your accounts."),
    "job_scam": ("A job pays Rs 5000 a day for liking videos, after a registration fee. Real?", ["Yes", "No, it is a task scam"], 1, "Genuine jobs never charge you to start earning."),
    "parcel": ("A courier message says pay a customs fee through a link. What now?", ["Pay quickly", "Check on the courier's official app"], 1, "Verify through the official app or website, never a link in a message."),
    "investment": ("A group promises guaranteed double money in 30 days. Trustworthy?", ["Yes", "No, nobody can guarantee that"], 1, "Guaranteed high returns are the main sign of investment fraud."),
}


def awareness(district: str | None = None, now: float | None = None) -> dict[str, Any]:
    now = now or time.time()
    since = now - 7 * DAY
    scope = "district" if district else "all"
    rows = []
    if district:
        rows = _rows("SELECT category, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' AND district=? AND category NOT IN ('none','urgency','impersonation','link_link','link_bait','block_threat') GROUP BY category ORDER BY n DESC LIMIT 1", (since, district))
    if not rows:
        scope = "all"
        rows = _rows("SELECT category, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' AND category NOT IN ('none','urgency','impersonation','link_link','link_bait','block_threat') GROUP BY category ORDER BY n DESC LIMIT 1", (since,))
    if not rows:
        return {"available": False}
    cat, n = rows[0]["category"], rows[0]["n"]
    tip = explain.WHY.get(cat) or {"en": "Be careful with unexpected messages that ask for money or codes.", "hi": "पैसे या कोड मांगने वाले अनजान संदेशों से सावधान रहें।", "pa": "ਪੈਸੇ ਜਾਂ ਕੋਡ ਮੰਗਣ ਵਾਲੇ ਅਣਜਾਣ ਸੁਨੇਹਿਆਂ ਤੋਂ ਸਾਵਧਾਨ ਰਹੋ।"}
    out = {"available": True, "scope": scope, "district": district if scope == "district" else None, "category": cat, "label": label(cat), "reports_7d": n, "tip": tip}
    q = PREBUNK.get(cat)
    if q:
        out["quiz"] = {"question": q[0], "options": q[1], "answer": q[2], "explanation": q[3]}
    return out


# ------------------------------------------------------------------ k-anonymous threat feed
def feed(days: int = 30) -> dict[str, Any]:
    cutoff = time.time() - days * DAY
    rows = _rows(
        "SELECT district, category, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' AND district IS NOT NULL GROUP BY district, category ORDER BY n DESC",
        (cutoff,),
    )
    items, suppressed = [], 0
    for r in rows:
        if r["n"] < K_ANON:
            suppressed += 1
            continue
        items.append({"district": r["district"], "category": r["category"], "reports": r["n"]})
    return {
        "schema": "surakshasathi.threat-feed/1", "window_days": days, "k_anonymity": K_ANON,
        "privacy": f"Cells with fewer than {K_ANON} reports are withheld. No phone numbers, names or message text are shared.",
        "suppressed_cells": suppressed, "items": items[:40],
    }
