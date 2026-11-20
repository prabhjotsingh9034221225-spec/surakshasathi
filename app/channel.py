"""Daily digest for the SurakshaSathi WhatsApp Channel: live alerts, district-wise report, top scams.

WhatsApp Channels have no public posting API, so the admin copies this text into the Channel.
Only aggregate counts are used; district cells below the k-anonymity floor are withheld.
"""
from __future__ import annotations

import time
from typing import Any

from . import alerts, intel

_GENERIC = "('none','urgency','impersonation','link_link','link_bait','block_threat')"
_T = {
    "en": {"title": "🛡️ SurakshaSathi Scam Report", "alerts": "🚨 Live alerts", "none": "No sudden spikes right now.", "top": "🔝 Top scams this week",
           "dist": "📍 District-wise (7 days)", "rep": "reports", "tip": "✅ Today's tip", "foot": "Lost money? Call 1930 at once. Check any message free: {url}", "quiet": "Not enough reports yet to publish."},
    "hi": {"title": "🛡️ सुरक्षासाथी ठगी रिपोर्ट", "alerts": "🚨 ताज़ा चेतावनी", "none": "अभी कोई अचानक उछाल नहीं।", "top": "🔝 इस हफ़्ते की शीर्ष ठगियाँ",
           "dist": "📍 जिलेवार (7 दिन)", "rep": "रिपोर्ट", "tip": "✅ आज की सलाह", "foot": "पैसे कट गए? तुरंत 1930 पर कॉल करें। कोई भी संदेश मुफ़्त जाँचें: {url}", "quiet": "प्रकाशित करने लायक रिपोर्ट अभी नहीं हैं।"},
    "pa": {"title": "🛡️ ਸੁਰੱਖਿਆਸਾਥੀ ਠੱਗੀ ਰਿਪੋਰਟ", "alerts": "🚨 ਤਾਜ਼ਾ ਚੇਤਾਵਨੀ", "none": "ਹੁਣ ਕੋਈ ਅਚਾਨਕ ਵਾਧਾ ਨਹੀਂ।", "top": "🔝 ਇਸ ਹਫ਼ਤੇ ਦੀਆਂ ਮੁੱਖ ਠੱਗੀਆਂ",
           "dist": "📍 ਜ਼ਿਲ੍ਹੇ ਅਨੁਸਾਰ (7 ਦਿਨ)", "rep": "ਰਿਪੋਰਟਾਂ", "tip": "✅ ਅੱਜ ਦੀ ਸਲਾਹ", "foot": "ਪੈਸੇ ਕੱਟੇ ਗਏ? ਤੁਰੰਤ 1930 ਤੇ ਕਾਲ ਕਰੋ। ਕੋਈ ਵੀ ਸੁਨੇਹਾ ਮੁਫ਼ਤ ਜਾਂਚੋ: {url}", "quiet": "ਛਾਪਣ ਲਈ ਅਜੇ ਕਾਫ਼ੀ ਰਿਪੋਰਟਾਂ ਨਹੀਂ।"},
}


def build(lang: str = "en", url: str = "", now: float | None = None, top_n: int = 5, districts_n: int = 6) -> dict[str, Any]:
    lang = lang if lang in _T else "en"
    t = _T[lang]
    now = now or time.time()
    since = now - 7 * 86400
    k = intel.K_ANON
    top = intel._rows(f"SELECT category, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' AND category NOT IN {_GENERIC} GROUP BY category ORDER BY n DESC LIMIT ?", (since, top_n))
    dist = intel._rows("SELECT district, COUNT(*) n FROM reports WHERE ts>=? AND verdict!='safe' AND district IS NOT NULL GROUP BY district HAVING n>=? ORDER BY n DESC LIMIT ?", (since, k, districts_n))
    for d in dist:
        c = intel._rows(f"SELECT category FROM reports WHERE ts>=? AND verdict!='safe' AND district=? AND category NOT IN {_GENERIC} GROUP BY category ORDER BY COUNT(*) DESC LIMIT 1", (since, d["district"]))
        d["top"] = intel.label(c[0]["category"]) if c else None
    live = alerts.active_alerts(now, min_level="watch")
    aw = intel.awareness(None, now)

    lines = [t["title"], ""]
    lines.append(t["alerts"])
    if live:
        lines += [f"• {a['district']}: {a['label']} ({a['count']} {t['rep']}, {a['hours']}h)" for a in live[:5]]
    else:
        lines.append(t["none"])
    lines += ["", t["top"]]
    lines += [f"{i}. {intel.label(r['category'])} ({r['n']})" for i, r in enumerate(top, 1)] or [t["quiet"]]
    lines += ["", t["dist"]]
    lines += [f"• {d['district']}: {d['n']} {t['rep']}" + (f", {d['top']}" if d["top"] else "") for d in dist] or [t["quiet"]]
    if aw.get("available"):
        tip = aw["tip"].get(lang) or aw["tip"].get("en")
        lines += ["", t["tip"], tip]
    lines += ["", t["foot"].format(url=url or "")]
    return {"lang": lang, "text": "\n".join(lines).strip(), "alerts": len(live), "top": [{"category": r["category"], "reports": r["n"]} for r in top],
            "districts": [{"district": d["district"], "reports": d["n"], "top": d["top"]} for d in dist]}
