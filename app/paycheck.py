"""'Before I pay' check: combines what other people reported about the payee with a few plain questions."""
from __future__ import annotations

from typing import Any

_FLAGS = ("stranger", "rushed", "to_receive", "secret", "new_payee", "name_mismatch", "authority")

_T = {
    "stop": {"en": "STOP. Do not send this money.", "hi": "रुकिए। यह पैसा न भेजें।", "pa": "ਰੁਕੋ। ਇਹ ਪੈਸੇ ਨਾ ਭੇਜੋ।"},
    "wait": {"en": "WAIT. Check first before you pay.", "hi": "ठहरिए। पैसे भेजने से पहले जाँच लें।", "pa": "ਠਹਿਰੋ। ਪੈਸੇ ਭੇਜਣ ਤੋਂ ਪਹਿਲਾਂ ਜਾਂਚ ਲਓ।"},
    "go": {"en": "No warning signs found. Pay only if you trust this person.", "hi": "कोई चेतावनी नहीं मिली। भरोसा हो तभी भेजें।", "pa": "ਕੋਈ ਚੇਤਾਵਨੀ ਨਹੀਂ ਮਿਲੀ। ਭਰੋਸਾ ਹੋਵੇ ਤਾਂ ਹੀ ਭੇਜੋ।"},
}
_R = {
    "to_receive": {"en": "You never need to pay or enter your PIN to RECEIVE money. This is the classic UPI scam.", "hi": "पैसे पाने के लिए कभी पैसे भेजने या PIN डालने की ज़रूरत नहीं होती। यह UPI ठगी का पुराना तरीका है।", "pa": "ਪੈਸੇ ਲੈਣ ਲਈ ਕਦੇ ਪੈਸੇ ਭੇਜਣ ਜਾਂ PIN ਪਾਉਣ ਦੀ ਲੋੜ ਨਹੀਂ ਹੁੰਦੀ। ਇਹ UPI ਠੱਗੀ ਦਾ ਪੁਰਾਣਾ ਤਰੀਕਾ ਹੈ।"},
    "authority": {"en": "Police, courts, banks and government offices never ask you to pay or move money to a 'safe account'.", "hi": "पुलिस, अदालत, बैंक या सरकारी दफ़्तर कभी 'सुरक्षित खाते' में पैसे भेजने को नहीं कहते।", "pa": "ਪੁਲਿਸ, ਅਦਾਲਤ, ਬੈਂਕ ਜਾਂ ਸਰਕਾਰੀ ਦਫ਼ਤਰ ਕਦੇ 'ਸੁਰੱਖਿਅਤ ਖਾਤੇ' ਵਿੱਚ ਪੈਸੇ ਭੇਜਣ ਨੂੰ ਨਹੀਂ ਕਹਿੰਦੇ।"},
    "secret_rushed": {"en": "Being told to keep it secret AND hurry is how scammers stop you from thinking or asking family.", "hi": "'किसी को मत बताओ' और 'जल्दी करो', ठग इसी से आपको सोचने या परिवार से पूछने नहीं देते।", "pa": "'ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ' ਅਤੇ 'ਜਲਦੀ ਕਰੋ', ਠੱਗ ਇਸੇ ਨਾਲ ਤੁਹਾਨੂੰ ਸੋਚਣ ਜਾਂ ਪਰਿਵਾਰ ਤੋਂ ਪੁੱਛਣ ਨਹੀਂ ਦਿੰਦੇ।"},
    "stranger_rushed": {"en": "A stranger who is rushing you to pay is the biggest warning sign.", "hi": "अनजान व्यक्ति जो जल्दी पैसे भेजने को कह रहा है, यह सबसे बड़ा खतरे का संकेत है।", "pa": "ਅਣਜਾਣ ਬੰਦਾ ਜੋ ਜਲਦੀ ਪੈਸੇ ਭੇਜਣ ਲਈ ਕਹਿ ਰਿਹਾ ਹੈ, ਇਹ ਸਭ ਤੋਂ ਵੱਡਾ ਖ਼ਤਰੇ ਦਾ ਨਿਸ਼ਾਨ ਹੈ।"},
    "reports_many": {"en": "This payee has been reported by several people on SurakshaSathi.", "hi": "इस खाते की SurakshaSathi पर कई लोगों ने शिकायत की है।", "pa": "ਇਸ ਖਾਤੇ ਦੀ SurakshaSathi ਤੇ ਕਈ ਲੋਕਾਂ ਨੇ ਸ਼ਿਕਾਇਤ ਕੀਤੀ ਹੈ।"},
    "reports_some": {"en": "This payee has been reported before.", "hi": "इस खाते की पहले शिकायत हो चुकी है।", "pa": "ਇਸ ਖਾਤੇ ਦੀ ਪਹਿਲਾਂ ਸ਼ਿਕਾਇਤ ਹੋ ਚੁੱਕੀ ਹੈ।"},
    "name_mismatch": {"en": "The name shown does not match who you expect. Do not pay until you are sure.", "hi": "दिखने वाला नाम उस व्यक्ति से नहीं मिलता जिसे आप जानते हैं। पक्का होने तक पैसे न भेजें।", "pa": "ਦਿਸਣ ਵਾਲਾ ਨਾਮ ਉਸ ਬੰਦੇ ਨਾਲ ਨਹੀਂ ਮਿਲਦਾ ਜਿਸਨੂੰ ਤੁਸੀਂ ਜਾਣਦੇ ਹੋ। ਪੱਕਾ ਹੋਣ ਤੱਕ ਪੈਸੇ ਨਾ ਭੇਜੋ।"},
    "stranger": {"en": "You do not know this person. Verify them another way first.", "hi": "आप इस व्यक्ति को नहीं जानते। पहले किसी और तरीके से पक्का करें।", "pa": "ਤੁਸੀਂ ਇਸ ਬੰਦੇ ਨੂੰ ਨਹੀਂ ਜਾਣਦੇ। ਪਹਿਲਾਂ ਕਿਸੇ ਹੋਰ ਤਰੀਕੇ ਨਾਲ ਪੱਕਾ ਕਰੋ।"},
    "rushed": {"en": "You are being rushed. Real payments can wait five minutes.", "hi": "आपको जल्दी करने को कहा जा रहा है। असली भुगतान पाँच मिनट रुक सकता है।", "pa": "ਤੁਹਾਨੂੰ ਜਲਦੀ ਕਰਨ ਲਈ ਕਿਹਾ ਜਾ ਰਿਹਾ ਹੈ। ਅਸਲੀ ਭੁਗਤਾਨ ਪੰਜ ਮਿੰਟ ਰੁਕ ਸਕਦਾ ਹੈ।"},
    "secret": {"en": "Anyone asking you to keep a payment secret from family is a red flag.", "hi": "जो भुगतान परिवार से छिपाने को कहे, यह खतरे की निशानी है।", "pa": "ਜੋ ਭੁਗਤਾਨ ਪਰਿਵਾਰ ਤੋਂ ਲੁਕਾਉਣ ਲਈ ਕਹੇ, ਇਹ ਖ਼ਤਰੇ ਦੀ ਨਿਸ਼ਾਨੀ ਹੈ।"},
    "new_payee": {"en": "First payment to a new payee: send a small test amount first if you can.", "hi": "नए व्यक्ति को पहली बार भुगतान: हो सके तो पहले थोड़ी रकम भेजकर देखें।", "pa": "ਨਵੇਂ ਬੰਦੇ ਨੂੰ ਪਹਿਲੀ ਵਾਰ ਭੁਗਤਾਨ: ਹੋ ਸਕੇ ਤਾਂ ਪਹਿਲਾਂ ਥੋੜ੍ਹੀ ਰਕਮ ਭੇਜ ਕੇ ਵੇਖੋ।"},
    "large": {"en": "This is a large amount. Call the person on a number you already trust.", "hi": "यह बड़ी रकम है। जिस नंबर पर आपको भरोसा है उसी पर व्यक्ति को कॉल करें।", "pa": "ਇਹ ਵੱਡੀ ਰਕਮ ਹੈ। ਜਿਸ ਨੰਬਰ ਤੇ ਭਰੋਸਾ ਹੈ ਉਸੇ ਤੇ ਬੰਦੇ ਨੂੰ ਕਾਲ ਕਰੋ।"},
}
_NEXT = {
    "stop": {"en": ["Do not pay and do not enter your UPI PIN.", "Talk to a family member or your bank.", "Lost money already? Call 1930 now."], "hi": ["पैसे न भेजें और UPI PIN न डालें।", "परिवार के किसी सदस्य या बैंक से बात करें।", "पैसे जा चुके हैं? अभी 1930 पर कॉल करें।"], "pa": ["ਪੈਸੇ ਨਾ ਭੇਜੋ ਅਤੇ UPI PIN ਨਾ ਪਾਓ।", "ਪਰਿਵਾਰ ਦੇ ਕਿਸੇ ਮੈਂਬਰ ਜਾਂ ਬੈਂਕ ਨਾਲ ਗੱਲ ਕਰੋ।", "ਪੈਸੇ ਜਾ ਚੁੱਕੇ ਹਨ? ਹੁਣੇ 1930 ਤੇ ਕਾਲ ਕਰੋ।"]},
    "wait": {"en": ["Call the person on a number you already know.", "Ask a family member before paying.", "Pay only when every answer feels right."], "hi": ["जिस नंबर को आप पहले से जानते हैं उसी पर कॉल करें।", "भेजने से पहले परिवार में किसी से पूछ लें।", "सब बातें सही लगें तभी भेजें।"], "pa": ["ਜਿਸ ਨੰਬਰ ਨੂੰ ਤੁਸੀਂ ਪਹਿਲਾਂ ਤੋਂ ਜਾਣਦੇ ਹੋ ਉਸੇ ਤੇ ਕਾਲ ਕਰੋ।", "ਭੇਜਣ ਤੋਂ ਪਹਿਲਾਂ ਪਰਿਵਾਰ ਵਿੱਚ ਕਿਸੇ ਤੋਂ ਪੁੱਛ ਲਓ।", "ਸਭ ਗੱਲਾਂ ਠੀਕ ਲੱਗਣ ਤਾਂ ਹੀ ਭੇਜੋ।"]},
    "go": {"en": ["Check the name shown before you confirm.", "Never share your UPI PIN with anyone."], "hi": ["पक्का करने से पहले दिखने वाला नाम जाँच लें।", "अपना UPI PIN किसी को न बताएँ।"], "pa": ["ਪੱਕਾ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਦਿਸਣ ਵਾਲਾ ਨਾਮ ਜਾਂਚ ਲਓ।", "ਆਪਣਾ UPI PIN ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ।"]},
}


def check(flags: dict[str, bool], amount: float | None, payee_reports: int, lang: str = "en") -> dict[str, Any]:
    lang = lang if lang in ("en", "hi", "pa") else "en"
    f = {k: bool(flags.get(k)) for k in _FLAGS}
    reasons: list[str] = []
    level = "go"

    def bump(to: str) -> None:
        nonlocal level
        level = to if {"go": 0, "wait": 1, "stop": 2}[to] > {"go": 0, "wait": 1, "stop": 2}[level] else level

    if f["to_receive"]:
        bump("stop"); reasons.append("to_receive")
    if f["authority"]:
        bump("stop"); reasons.append("authority")
    if f["secret"] and f["rushed"]:
        bump("stop"); reasons.append("secret_rushed")
    elif f["stranger"] and f["rushed"]:
        bump("stop"); reasons.append("stranger_rushed")
    if payee_reports >= 3:
        bump("stop"); reasons.append("reports_many")
    elif payee_reports >= 1:
        bump("wait"); reasons.append("reports_some")
    if not ("secret_rushed" in reasons or "stranger_rushed" in reasons):
        for k in ("stranger", "rushed", "secret"):
            if f[k]:
                bump("wait"); reasons.append(k)
    if f["name_mismatch"]:
        bump("wait"); reasons.append("name_mismatch")
    if f["new_payee"]:
        bump("wait" if (amount or 0) >= 5000 or level != "go" else "go"); reasons.append("new_payee")
    if (amount or 0) >= 50000 and level == "go":
        bump("wait"); reasons.append("large")
    elif (amount or 0) >= 50000:
        reasons.append("large")
    return {
        "level": level,
        "headline": _T[level][lang],
        "reasons": [_R[r][lang] for r in reasons],
        "next_steps": _NEXT[level][lang],
    }
