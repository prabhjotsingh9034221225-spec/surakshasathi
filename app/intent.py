"""Intent layer: scores the *shape* of a scam, not its exact words.

Keyword rules only catch scams someone has already seen. Almost every scam, however it is
worded, is a combination of the same few ingredients: a demand for money or a secret, a fake
authority, a threat or a lure, pressure to act now, and a number or link to act on. This module
detects those ingredients (English, Hinglish, Hindi, Punjabi) and scores the combination.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_F = re.IGNORECASE | re.DOTALL
_NUM = r"(?:rs\.?|₹|inr|rupees?|rupaye|rupay|रुपये|रुपए|रु\.?|ਰੁਪਏ)"
_MOBILE = r"(?:\+?91[\s-]?)?[6-9]\d{9}"
_VERB_PAY = r"(?:pay|send|transfer|deposit|invest(?:ment)?|remit|wire|daal\w*|dalo|dal do|bhej\w*|jama|भेज\w*|जमा|भरें|भरो|भरना|ਭੇਜੋ|ਭਰੋ|ਜਮ੍ਹਾ|ਭਰਨ)"


def _c(*pats: str) -> list[re.Pattern[str]]:
    return [re.compile(p, _F) for p in pats]


FAMILIES: dict[str, list[re.Pattern[str]]] = {
    # An actual demand for money (not just a bill reminder; combos below decide).
    "money": _c(
        r"\b(?:transfer|send|move|shift)\b.{0,30}\b(?:your )?(?:balance|savings|entire amount|all (?:your )?(?:money|funds))\b|\bsafe account\b",
        rf"\b{_VERB_PAY}\b.{{0,60}}(?:{_NUM}\s?\d|\d[\d,]{{2,}}\s?{_NUM}?)",
        rf"{_NUM}\s?\d[\d,]*.{{0,50}}\b(?:{_VERB_PAY}|fee|charges?|duty|fine|settlement|deposit)\b",
        r"\b(?:processing|registration|release|clearance|customs|delivery|verification|activation|handling|security|advance|token|bail|medical)\s?(?:fees?|charges?|duty|amount|deposit|money)\b",
        rf"{_NUM}.{{0,30}}(?:भेज|जमा|भरो|भरें|भुगतान|ਭੇਜੋ|ਭਰੋ|ਜਮ੍ਹਾ)",
        rf"(?:भेज|जमा|भरें|ਭੇਜੋ|ਭਰੋ|ਜਮ੍ਹਾ).{{0,30}}(?:{_NUM}|रुपये|ਰੁਪਏ|ਪੈਸੇ|पैसे)",
        r"(?:फीस|शुल्क|ਫੀਸ|ਚਾਰਜ).{0,25}(?:भरो|भरें|जमा|ਭਰੋ|ਜਮ੍ਹਾ|ਭਰਨ)",
        r"\b(?:\d{3,6})\s?(?:rupaye|rs|रुपये|ਰੁਪਏ)\b.{0,30}(?:fee|फीस|ਫੀਸ|charge|clearance)",
        r"\b(?:phonepe|gpay|google ?pay|paytm|upi)\b.{0,30}\b(?:kar do|karo|kar de|bhej)\b",
        r"\b(?:send|pay|return|transfer)\b.{0,15}\b(?:back|it back)\b|\b(?:return|wapas|lauta\w*)\b.{0,30}(?:to|ko)\b.{0,20}[6-9]\d{9}",
        rf"\b\d[\d,]{{2,}}\s?(?:rs|rupaye|rupees?|rupay)?\b.{{0,25}}\b(?:bhej\w*|daal\w*|dalo|dal do|kar do|transfer|jama|jmaa|deposit|pay)\b",
    ),
    # A prize, refund, bonus, easy income or "too good to be true" offer.
    "lure": _c(
        r"\b(?:won|winner|prize|lucky draw|lottery|jackpot|bumper|congratulations|cashback|refund|bonus|subsidy|reward|selected for|hiring|free (?:iphone|netflix|recharge|gift|laptop|data)|inaam|inam)\b",
        r"\b(?:earn|income|salary)\b.{0,30}(?:per|daily|a day|/day|/month|monthly|every)",
        r"\b(?:mobile )?tower\b.{0,60}\b(?:rent|installation)\b|\b(?:milega|milenge)\b.{0,40}\d{4,}",
        r"\b(?:donat(?:e|ion)|inherit(?:ance)?|million dollars|beneficiary|unclaimed (?:funds|money)|next of kin|compensation|scholarship)\b",
        r"\b(?:sell your old|old coins|buyers are waiting|lakhs for)\b",
        r"\b(?:double (?:hoga|ho jayega|ho jaega|kar|paisa)|paisa lagao|crypto|bitcoin|forex)\b",
        r"\b(?:guaranteed|daily (?:profit|returns?)|\d{2,4}% (?:profit|returns?)|double your|returns? in \d+ days?|profit in \d+ days?)\b",
        r"\b(?:work from home|part[- ]time|online (?:job|work|tasks?)|simple (?:online )?tasks?|daily (?:payment|income)|product reviewer|rate (?:hotels|products|videos))\b",
        r"\b(?:make|earn)\b.{0,15}(?:rs\.?|₹)\s?[\d,]+.{0,15}(?:per|a|/)\s?(?:month|day|week|hour)\b",
        r"\bloan\b.{0,40}\b(?:approved|sanctioned|passed)\b",
        r"(?:ਲੋਨ|लोन).{0,40}(?:ਮਨਜ਼ੂਰ|मंजूर|पास|स्वीकृत)",
        r"\b(?:cheap|low price|below market).{0,40}(?:advance|booking|token)|\b(?:advance|booking|token).{0,40}(?:cheap|sell)",
        r"(?:लॉटरी|इनाम|बधाई|रिफंड|कैशबैक|सब्सिडी|योजना|मुफ्त|मुनाफा)",
        r"(?:ਲਾਟਰੀ|ਇਨਾਮ|ਵਧਾਈ|ਰਿਫੰਡ|ਕੈਸ਼ਬੈਕ|ਮੁਫ਼ਤ|ਮੁਨਾਫ਼ਾ)",
    ),
    # Someone claiming to be a bank, government body, officer, support agent or company.
    "authority": _c(
        r"\b(?:police|cbi|ed officer|cyber ?(?:cell|crime)|crime branch|high court|supreme court|court|customs|trai|rbi|income ?tax|uidai|npci|dot|epfo|lic|army|major|colonel|inspector|officer|head office|customer (?:care|support)|support team|executive|microsoft|amazon|flipkart|paytm|sbi|hdfc|icici|axis|pnb|bank|government|ministry|electricity (?:board|department)|engineer)\b",
        r"\b(?:this is|i am|calling from|speaking from|main .{0,25} se bol)\b.{0,40}\b(?:bank|police|support|officer|department|office|care)\b",
        r"(?:पुलिस|न्यायालय|अदालत|सीबीआई|आरबीआई|बैंक|अधिकारी|सरकार|आधार|बिजली विभाग)",
        r"(?:ਪੁਲਿਸ|ਅਦਾਲਤ|ਬੈਂਕ|ਅਧਿਕਾਰੀ|ਸਰਕਾਰ|ਆਧਾਰ|ਬਿਜਲੀ ਵਿਭਾਗ)",
    ),
    # Fear of the state: arrest, case, illegal items.
    "state_threat": _c(
        r"\b(?:aadhaar|sim|number|account|parcel)\b.{0,50}\b(?:used in|linked to|involved in|found (?:in|with)|connected to)\b.{0,40}\b(?:fraud|illegal|crime|laundering|terror\w*|smuggling|counterfeit)\b",
        r"\b(?:counterfeit|smuggling|terror\w*)\b",
        r"\b(?:defaulters?|seizure|attachment of|recovery notice|legal notice|blacklist(?:ed)?|arrest(?:ed)?|custody|jail|summon(?:ed|s)?|warrant|fir\b|case (?:is |has been )?(?:filed|registered)|legal action|cheque bounce|giraftar|giraftari|pakda|pakad|seized|illegal|drugs?|mdma|narcotics|money laundering|under investigation|contempt)\b",
        r"(?:गिरफ्तार|हिरासत|जेल|वारंट|अवैध|ड्रग|मुकदमा|कानूनी कार्रवाई|केस दर्ज)",
        r"(?:ਗ੍ਰਿਫ਼ਤਾਰ|ਹਿਰਾਸਤ|ਜੇਲ੍ਹ|ਵਾਰੰਟ|ਗੈਰ-?ਕਾਨੂੰਨੀ|ਕੇਸ ਦਰਜ)",
    ),
    # Fear of losing an account, SIM, connection or card.
    "account_threat": _c(
        r"\b(?:barred|barring|on hold|non-?compliance|mismatch|block(?:ed)?|suspend(?:ed)?|frozen|freeze|deactivat\w*|disconnect\w*|cancel(?:led|lation)?|terminat\w*|expire[sd]?|stopped|locked|closed|cut off|will be cut|band ho|kat jayega|band ho jayega)\b",
        r"\b(?:kyc|e-?kyc|pan|aadhaar)\b.{0,40}\b(?:pending|incomplete|expired|expire|mandatory|required|update)\b",
        r"(?:बंद हो|ब्लॉक|निलंबित|कट जाएगा|कनेक्शन कट|काट दिया|कट जाए|रद्द|एक्सपायर)",
        r"(?:ਬੰਦ ਹੋ|ਬਲੌਕ|ਬਲਾਕ|ਕੱਟ|ਰੱਦ|ਮਿਆਦ ਖਤਮ)",
    ),
    "parcel": _c(
        r"\b(?:parcel|package|courier|shipment|consignment|gift package)\b.{0,80}\b(?:held|stuck|seized|customs|clearance|undelivered|detained|airport)\b",
        r"(?:पार्सल|कूरियर).{0,60}(?:रुक|कस्टम|जब्त|फंस)",
        r"(?:ਪਾਰਸਲ|ਕੋਰੀਅਰ).{0,60}(?:ਰੁਕ|ਕਸਟਮ|ਜ਼ਬਤ|ਫਸ)",
    ),
    "wrong_transfer": _c(
        r"\b(?:by mistake|mistakenly|wrongly|galti se)\b.{0,100}\b(?:credited|sent|transferred|deposit\w*|bhej\w*)\b",
        r"\b(?:credited|sent|transferred)\b.{0,60}\b(?:by mistake|mistakenly|wrongly|galti se)\b",
    ),
    "urgency": _c(
        r"\b(?:immediately|urgent(?:ly)?|right now|asap|today|tonight|within \d+ ?(?:hours?|hrs?|mins?|minutes?)|last (?:warning|chance|notice)|final notice|at once|turant|abhi|jaldi|aaj hi|aaj raat|foran)\b",
        r"(?:तुरंत|फौरन|अभी|जल्दी|आज रात|आज ही|ਤੁਰੰਤ|ਹੁਣੇ|ਜਲਦੀ|ਅੱਜ ਰਾਤ)",
    ),
    "secrecy": _c(
        r"\b(?:do not|don'?t|dont|never|mat|nahi|not)\b.{0,15}\b(?:tell|inform|disconnect|cut|hang up|batana|bataana|batao|kaatna)\b",
        r"\b(?:call kaatna mat|kisi ko mat|stay on (?:the )?(?:line|call)|keep (?:this|it) secret)\b",
        r"(?:किसी को (?:मत|न|नहीं) बता|कॉल (?:मत )?काट)",
        r"(?:ਕਿਸੇ ਨੂੰ (?:ਨਾ|ਨਹੀਂ) ਦੱਸ|ਕਾਲ ਨਾ ਕੱਟ)",
    ),
    # Asks for a secret (OTP, PIN, CVV, card/account number, "the code").
    "secret": _c(
        rf"\b(?:send|share|enter|tell|give|provide|confirm|reply with|forward|bata\w*|bhej\w*|dalo|daalo|dalein|दें|बताएं|बताओ|भेजें|भेजो|डालें|दर्ज|ਦੱਸੋ|ਭੇਜੋ|ਦਿਓ)\b.{{0,50}}\b(?:otp|pin|cvv|cvc|password|passcode|card number|card details|expiry|account number|bank account|aadhaar number|code|ओटीपी|पिन|खाता नंबर|ਓਟੀਪੀ|ਪਿੰਨ)\b",
        r"\b(?:otp|pin|cvv|ओटीपी|पिन|ਓਟੀਪੀ|ਪਿੰਨ)\b.{0,40}\b(?:send|share|tell|give|bata\w*|bhej\w*|दें|बताएं|भेजें|ਦੱਸੋ|ਭੇਜੋ)\b",
        r"\b(?:card number|account number|bank account)\b.{0,40}\b(?:otp|pin|cvv|expiry)\b",
        r"(?:ਆਪਣਾ|अपना)\s?(?:otp|ओटीपी|ਓਟੀਪੀ|pin|पिन|ਪਿੰਨ)",
    ),
    # A phone number or link to act on: the "call me / click here" exit from the message.
    "call_mobile": _c(
        rf"\b(?:call|contact|whatsapp|dial|phone|ring|baat karein|sampark|संपर्क|कॉल|ਕਾਲ|ਸੰਪਰਕ)\b.{{0,50}}{_MOBILE}\b",
        rf"{_MOBILE}\b.{{0,30}}\b(?:call|whatsapp|contact|now)\b",
        r"\bcall (?:the )?(?:cyber|police|officer|engineer|executive|number)\b",
    ),
    "link": _c(
        r"https?://|\bwww\.|bit\.ly|tinyurl|t\.me/|\.(?:top|click|xyz|site|icu|online|cc|info)\b",
        r"\b(?:link|लिंक|ਲਿੰਕ)\b.{0,30}\b(?:click|open|tap|क्लिक|खोलें|ਕਲਿੱਕ)",
        r"\b(?:click|open|tap|क्लिक|खोलें|ਕਲਿੱਕ)\b.{0,20}\b(?:link|here|below|लिंक|ਲਿੰਕ)",
        r"\b(?:telegram|whatsapp group|join our)\b",
    ),
    "install": _c(
        r"\b(?:install|download)\b.{0,40}\b(?:app|apk|anydesk|teamviewer|quick ?support|rustdesk)\b",
        r"\b(?:anydesk|teamviewer|quick ?support|rustdesk|screen ?share)\b",
        r"\.apk\b",
    ),
    "family": _c(
        r"\b(?:son|daughter|beta|beti|bhai|bhaiya|brother|sister|mom|mum|mummy|papa|dad|uncle|aunty|husband|wife|nephew|relative)\b.{0,100}\b(?:accident|custody|hospital|surgery|arrested|bail|stuck|abroad|emergency|new number|naya number|nayi sim|new sim|lost (?:my )?phone|phone (?:kharab|kho gaya|gir gaya|broke|toot)|bharti|admit)\b",
        r"\b(?:stuck|stranded) abroad\b|\blost (?:my )?(?:wallet|passport)\b",
        r"(?:बेटा|बेटी|भाई|पापा|मम्मी).{0,60}(?:एक्सीडेंट|हादसा|अस्पताल|गिरफ्तार|नया नंबर)",
        r"(?:ਪੁੱਤਰ|ਧੀ|ਭਰਾ|ਪਾਪਾ|ਮੰਮੀ).{0,60}(?:ਹਾਦਸਾ|ਹਸਪਤਾਲ|ਗ੍ਰਿਫ਼ਤਾਰ|ਨਵਾਂ ਨੰਬਰ)",
    ),
    # "A payment is being made from your account. If it is not you, call <mobile>" — the fake alert.
    "fake_alert": _c(
        r"(?:ਸ਼ੱਕੀ|संदिग्ध|अनधिकृत|ਅਣਅਧਿਕਾਰਤ).{0,30}(?:ਲੈਣ-?ਦੇਣ|लेन-?देन|transaction)",
        rf"\b(?:being (?:made|debited|processed)|has been (?:debited|initiated)|unauthori[sz]ed|suspicious (?:login|activity|transaction))\b.{{0,120}}\b(?:not you|if not|call|contact)\b",
        rf"\b(?:if (?:it is |this is )?not you|agar aap nahi|अगर आप नहीं)\b.{{0,60}}{_MOBILE}",
    ),
}

# Genuine messages point people to official channels and toll-free numbers, not a stranger's mobile.
_OFFICIAL = re.compile(
    r"\b(?:official (?:app|portal|website|site|office)|your (?:nearest )?branch|visit (?:the |your )?(?:branch|office|bank)|toll[- ]free|helpline|1800[\s-]?\d|1860[\s-]?\d|"
    r"customer care number on (?:the )?back|never share|do not share|don'?t share|banks? (?:never|will never)|आधिकारिक|ਅਧਿਕਾਰਤ)\b",
    _F,
)
_ADVICE = re.compile(r"\b(?:never|do not|don'?t|dont)\s+(?:share|tell|give|send|disclose)\b|कभी नहीं|किसी को न|ਕਿਸੇ ਨੂੰ ਨਾ", _F)


@dataclass
class IntentResult:
    families: set[str]
    score: int
    category: str | None
    reason: str | None


def families_in(text: str) -> set[str]:
    return {name for name, pats in FAMILIES.items() if any(p.search(text) for p in pats)}


def score(text: str) -> IntentResult:
    fam = families_in(text)
    has = fam.__contains__
    best, cat, why = 0, None, None

    def hit(points: int, category: str, reason: str) -> None:
        nonlocal best, cat, why
        if points > best:
            best, cat, why = points, category, reason

    pressure = has("urgency") or has("secrecy")
    act = has("call_mobile") or has("link")

    if has("money") and has("state_threat"):
        hit(68, "legal_threat", "money + state threat")
    if has("state_threat") and has("authority") and (act or pressure):
        hit(62, "legal_threat", "fake authority + threat + act-now")
    if has("secrecy") and has("state_threat"):
        hit(64, "legal_threat", "threat + secrecy")
    if has("family") and has("money"):
        hit(62, "family_impersonation", "family emergency + money")
    if has("money") and has("lure"):
        hit(58, "advance_fee", "reward/offer + money up front")
    if has("money") and has("authority") and (pressure or act or has("account_threat")):
        hit(56, "advance_fee", "authority + money + pressure")
    if has("lure") and act and (has("authority") or has("money") or "won" in text or "win " in text):
        hit(52, "lottery", "prize/offer + number or link to act on")
    if has("account_threat") and has("call_mobile") and (has("authority") or has("urgency") or "kyc" in text):
        hit(58, "block_threat", "account threat + call a mobile number")
    if has("account_threat") and has("link") and (has("authority") or has("urgency")):
        hit(56, "block_threat", "account threat + link")
    if has("fake_alert") and has("call_mobile"):
        hit(60, "block_threat", "fake transaction alert + call a mobile")
    if has("secret") and (has("authority") or pressure or has("lure") or has("account_threat")) and not _ADVICE.search(text):
        hit(66, "otp", "asks for a secret under pressure")
    if has("install") and (has("authority") or has("lure") or "support" in text or "refund" in text):
        hit(62, "remote_access", "install an app on a stranger's request")
    if has("wrong_transfer") and (has("money") or has("call_mobile") or re.search(r"\b(?:return|send back|wapas|refund)\b", text)):
        hit(60, "wrong_transfer", "'sent by mistake' + asks you to send it back")
    if has("money") and has("parcel"):
        hit(60, "parcel", "parcel held + fee to release")
    if has("lure") and has("link") and re.search(r"\b(?:earn|invest|profit|returns?|income|salary)\b", text):
        hit(55, "job_scam", "earning/investment offer + join/click")
    if has("lure") and has("money") and has("link"):
        hit(64, "advance_fee", "offer + money + link")

    if best and _OFFICIAL.search(text) and not has("call_mobile") and not has("state_threat"):
        best = int(best * 0.4)  # genuine notices point to official channels, not a stranger's number
    return IntentResult(fam, min(best, 100), cat, why)
