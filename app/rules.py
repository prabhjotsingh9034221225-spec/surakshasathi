"""Rule-based scam detector.

Fast, offline and explainable. Patterns cover English, Hindi (Devanagari),
Hinglish (romanised Hindi) and Punjabi (Gurmukhi + romanised). Each rule has a
category, a weight, and a reason key that i18n.py turns into a one-line
explanation in the user's language.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: int
    patterns: tuple[str, ...]


@dataclass
class RuleHit:
    rule_id: str
    category: str
    weight: int
    matched: str


@dataclass
class RuleResult:
    score: int
    hits: list[RuleHit] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    protective: bool = False


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = text.lower()
    return re.sub(r"\s+", " ", text).strip()


# Words meaning "send / share / tell / give" across the supported languages.
_ASK = (
    r"(?:send|share|tell|give|provide|enter|submit|forward|confirm|reply|bata(?:o|iye|na)?|bhej(?:o|iye|na)?|"
    r"de(?:do|na|iye)?|dijiye|batao|bolo|dasso|dass|bhejo|shere?|साझा|बताएं|बताओ|बताइए|भेजें|भेजो|दें|दीजिए|दो|"
    r"बताओ|भेजिए|ਦੱਸੋ|ਦੱਸ|ਭੇਜੋ|ਦਿਓ|ਸਾਂਝਾ)"
)

RULES: tuple[Rule, ...] = (
    # ---- Credentials: the single strongest signal --------------------------
    Rule("ask_otp", "otp", 62, (
        rf"{_ASK}.{{0,40}}\botp\b",
        rf"\botp\b.{{0,40}}{_ASK}",
        rf"{_ASK}.{{0,40}}(?:ओटीपी|ਓਟੀਪੀ)",
        rf"(?:ओटीपी|ਓਟੀਪੀ).{{0,40}}{_ASK}",
        r"\bone[- ]time[- ]password\b.{0,40}(?:share|send|tell|give)",
        r"\botp\b.{0,20}(?:required|needed|zaroori|chahiye|चाहिए)",
    )),
    Rule("ask_pin", "pin", 65, (
        rf"{_ASK}.{{0,40}}\b(?:upi\s*)?pin\b",
        rf"\b(?:upi\s*|atm\s*|mpin\s*)pin\b.{{0,40}}{_ASK}",
        rf"(?:पिन|ਪਿੰਨ).{{0,30}}{_ASK}",
        rf"{_ASK}.{{0,30}}(?:पिन|ਪਿੰਨ)",
        r"\b(?:cvv|card number|card details|atm pin|debit card|credit card)\b.{0,40}(?:share|send|tell|give|enter|verify|update)",
        rf"{_ASK}.{{0,30}}(?:cvv|कार्ड नंबर|कार्ड की जानकारी)",
    )),
    Rule("ask_password", "credentials", 55, (
        r"\b(?:password|passcode|net ?banking|login details|user ?id)\b.{0,40}(?:share|send|tell|give|enter|verify|update)",
        r"(?:share|send|tell|give|enter|verify|update).{0,40}\b(?:password|passcode|net ?banking)\b",
    )),
    # ---- Account block / KYC ------------------------------------------------
    Rule("kyc_update", "kyc", 35, (
        r"\bkyc\b.{0,60}(?:update|expire|expired|pending|verify|verification|incomplete|suspend|block)",
        r"(?:update|complete|verify|renew).{0,30}\bkyc\b",
        r"\bkyc\b.{0,60}(?:अपडेट|बंद|ब्लॉक|ਅਪਡੇਟ|ਬੰਦ)",
        r"(?:केवाईसी|ਕੇਵਾਈਸੀ)",
        r"\bpan\b.{0,40}(?:update|link|verify|block|suspend|expire)",
        r"\baadhaar\b.{0,40}(?:update|link|verify|block|suspend|expire)",
    )),
    Rule("account_blocked", "block_threat", 35, (
        r"(?:account|a/c|acct|card|sim|upi|wallet|number|connection).{0,40}(?:block(?:ed)?|suspend(?:ed)?|deactivat(?:e|ed)|freez(?:e|ing)|frozen|close(?:d)?|disconnect(?:ed)?|terminat(?:e|ed)|expire(?:d|s)?|restrict(?:ed)?)",
        r"(?:block(?:ed)?|suspend(?:ed)?|deactivat(?:e|ed)|freez(?:e|ing)|disconnect(?:ed)?).{0,40}(?:account|a/c|card|sim|upi|number|connection)",
        r"(?:खाता|अकाउंट|कार्ड|सिम|बिजली|कनेक्शन|नंबर).{0,40}(?:बंद|ब्लॉक|ब्लॉक|सस्पेंड|कट|रद्द|फ्रीज़|फ्रीज)",
        r"(?:ਖਾਤਾ|ਅਕਾਊਂਟ|ਕਾਰਡ|ਸਿਮ|ਬਿਜਲੀ|ਕੁਨੈਕਸ਼ਨ).{0,40}(?:ਬੰਦ|ਬਲੌਕ|ਬਲਾਕ|ਕੱਟ|ਰੱਦ)",
        r"(?:khata|account|card|sim|bijli|connection).{0,30}(?:band|block|kat|katt|suspend)\b",
        r"will be (?:blocked|suspended|disconnected|closed|deactivated)",
    )),
    # ---- Urgency / fear -----------------------------------------------------
    Rule("urgency", "urgency", 15, (
        r"\b(?:immediately|urgent(?:ly)?|right now|within \d+ ?(?:hours?|hrs?|mins?|minutes?)|today only|last chance|final (?:notice|warning)|act now|asap|expires? (?:today|tonight|soon))\b",
        r"\b(?:turant|jaldi|abhi|aaj hi|foran)\b",
        r"(?:तुरंत|फौरन|अभी|जल्दी|आज ही|आखिरी मौका|24 घंटे|२४ घंटे)",
        r"(?:ਤੁਰੰਤ|ਹੁਣੇ|ਜਲਦੀ|ਅੱਜ ਹੀ|ਆਖਰੀ ਮੌਕਾ)",
    )),
    Rule("legal_threat", "legal_threat", 30, (
        r"\b(?:arrest(?:ed)?|warrant|fir\b|police case|legal action|court notice|cyber ?crime branch|cbi|ed officer|narcotics|customs)\b.{0,80}(?:pay|fine|fee|transfer|verify|call|video)",
        r"(?:गिरफ्तार|वारंट|पुलिस केस|कानूनी कार्रवाई|सीबीआई)",
        r"(?:ਗ੍ਰਿਫ਼ਤਾਰ|ਵਾਰੰਟ|ਪੁਲਿਸ ਕੇਸ)",
        r"\bpolice\b.{0,40}\b(?:video call|skype|whatsapp call)\b",
    )),
    # "Digital arrest" does not exist in Indian law; the phrase itself is the giveaway.
    Rule("digital_arrest", "legal_threat", 65, (
        r"\bdigital(?:ly)? arrest(?:ed)?\b",
        r"(?:डिजिटल अरेस्ट|डिजिटल गिरफ्तारी)",
        r"(?:ਡਿਜੀਟਲ ਅਰੈਸਟ|ਡਿਜੀਟਲ ਗ੍ਰਿਫ਼ਤਾਰੀ)",
        r"\b(?:cbi|police|ed|narcotics|customs|trai|cyber ?crime)\b.{0,100}(?:stay on (?:the )?(?:video )?call|do not (?:disconnect|cut) (?:the )?call|keep (?:the )?(?:video )?call on)",
    )),
    # ---- Money for nothing --------------------------------------------------
    Rule("lottery_prize", "lottery", 40, (
        r"\b(?:lottery|lucky draw|jackpot)\b.{0,80}\b(?:won|win|winner|selected|prize|claim|crore|lakh|lakhs|credited|nikli|nikla)\b",
        r"\b(?:won|winner|selected|congratulations).{0,80}\b(?:lottery|lucky draw|jackpot)\b",
        r"\byou(?:'ve| have)? (?:just )?won\b",
        r"\bcongratulations\b.{0,40}\b(?:won|winner|selected)\b",
        r"\b(?:kbc|kaun banega)\b",
        r"\b(?:cash ?prize|gift voucher|free gift)\b",
        r"\breward points?\b.{0,20}(?:expire|redeem)",
        r"(?:लॉटरी|लकी ड्रा).{0,60}(?:जीत|इनाम|निकली|करोड़|लाख|जमा)",
        r"(?:जीत|इनाम).{0,60}(?:लॉटरी|लकी ड्रा)",
        r"(?:ਲਾਟਰੀ|ਇਨਾਮ).{0,60}(?:ਜਿੱਤ|ਇਨਾਮ|ਲੱਖ|ਕਰੋੜ)",
        r"(?:ਜਿੱਤ|ਜਿੱਤੀ).{0,60}(?:ਲਾਟਰੀ|ਇਨਾਮ)",
        r"\b(?:inaam|inam)\b.{0,40}\b(?:jeet|jita|jeeta|mila|nikla)\b",
        r"\blottery (?:nikli|nikla|lagi)\b",
    )),
    Rule("advance_fee", "advance_fee", 35, (
        r"\b(?:processing fee|registration fee|release fee|claim fee|customs fee|clearance fee|insurance fee|gst fee|tax to claim)\b",
        r"(?:pay|deposit|transfer|send).{0,30}(?:₹|rs\.?|inr)\s?\d[\d,]*.{0,40}(?:to (?:claim|receive|release|get|unlock)|fee|charges)",
        r"(?:प्रोसेसिंग फीस|रजिस्ट्रेशन फीस|चार्ज जमा|फीस जमा)",
        r"(?:ਪ੍ਰੋਸੈਸਿੰਗ ਫੀਸ|ਫੀਸ ਜਮ੍ਹਾ)",
    )),
    Rule("job_scam", "job_scam", 30, (
        r"\b(?:work from home|part[- ]time job|earn (?:₹|rs\.?)?\s?\d[\d,]*\s?(?:per|/)\s?(?:day|hour|week)|task (?:job|based)|like (?:and|&) (?:earn|subscribe)|youtube like|data entry job)\b",
        r"(?:घर बैठे कमाएं|पार्ट टाइम जॉब|रोज़ कमाएं|रोज कमाएं)",
        r"(?:ਘਰ ਬੈਠੇ ਕਮਾਓ|ਪਾਰਟ ਟਾਈਮ ਨੌਕਰੀ)",
    )),
    Rule("investment_scam", "investment", 60, (
        r"\b(?:guaranteed returns?|double your (?:money|investment)|100% (?:profit|return)|crypto (?:giveaway|trading tips)|stock tips? (?:group|vip)|ipo allotment guaranteed|risk[- ]free profit)\b",
        r"(?:पैसा दोगुना|गारंटीड रिटर्न|100% मुनाफा)",
        r"(?:ਪੈਸਾ ਦੁੱਗਣਾ|ਗਾਰੰਟੀਸ਼ੁਦਾ)",
    )),
    # ---- Payment tricks -----------------------------------------------------
    Rule("fake_collect", "upi_collect", 45, (
        r"\b(?:collect request|payment request|upi request|requested money|request from)\b.{0,60}(?:approve|accept|enter (?:your )?pin|pin)",
        r"(?:accept|approve).{0,30}(?:collect|request).{0,60}(?:receive|get|refund|cashback|prize|money)",
        r"to receive (?:money|payment|refund|cashback|prize).{0,40}(?:enter|put|type).{0,20}pin",
        r"(?:refund|cashback|paisa|money).{0,50}(?:pin|upi pin).{0,30}(?:daalo|dalo|dalein|enter|डालें|डालो)",
        r"(?:पैसे|रिफंड|कैशबैक).{0,50}(?:पिन).{0,30}(?:डालें|डालो|दर्ज)",
    )),
    # Genuine mistakes happen, so this alone is only "suspicious": do not send money back yourself.
    Rule("wrong_transfer", "wrong_transfer", 45, (
        r"wrong(?:ly)? (?:sent|transferred|credited).{0,60}(?:return|refund|send back|wapas|back)",
        r"(?:sent|transferred).{0,30}by mistake.{0,60}(?:return|refund|send back|wapas|back)",
        r"(?:galti se|galat).{0,60}(?:paise|paisa|payment|rupaye|rupay|rupees?|rs\.?|amount|₹).{0,60}(?:bhej|transfer|wapas|return|lauta)",
        r"(?:galti se|galat).{0,60}(?:aa gaye|aa gaya|credit|jama).{0,60}(?:wapas|bhej|return|lauta)",
        r"(?:गलती से|गलत).{0,60}(?:पैसे|रुपये|भुगतान|राशि).{0,60}(?:भेज|वापस|लौटा)",
        r"(?:ਗਲਤੀ ਨਾਲ).{0,60}(?:ਪੈਸੇ|ਰੁਪਏ).{0,60}(?:ਭੇਜ|ਵਾਪਸ|ਮੋੜ)",
    )),
    Rule("family_impersonation", "family_impersonation", 45, (
        r"(?:new|naya|nayi|naye|नया|नई|ਨਵਾਂ|ਨਵੀਂ).{0,25}(?:number|no\.?|नंबर|ਨੰਬਰ).{0,120}(?:send|transfer|bhejo|bhej do|bhej de|भेजो|भेज दो|ਭੇਜੋ|pay|paytm|gpay|phonepe)",
        r"(?:mummy|mom|mum|papa|dad|beta|bhaiya|मम्मी|पापा|बेटा|ਮੰਮੀ|ਪਾਪਾ).{0,40}(?:phone|mobile|फोन|ਫੋਨ).{0,30}(?:kharab|broke|lost|खराब|खो|ਖਰਾਬ|ਗੁੰਮ).{0,120}(?:send|bhejo|भेजो|ਭੇਜੋ|transfer|pay)",
    )),
    Rule("remote_access_app", "remote_access", 60, (
        r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|ammyy|airdroid|screen ?shar(?:e|ing)|remote (?:access|support|control))\b",
        r"(?:एनीडेस्क|टीमव्यूअर|स्क्रीन शेयर)",
    )),
    Rule("apk_download", "malware", 40, (
        r"\b\S+\.apk\b",
        r"\b(?:download|install).{0,30}(?:apk|app from (?:link|whatsapp))\b",
        r"(?:apk).{0,20}(?:डाउनलोड|install|download|इंस्टॉल)",
    )),
    Rule("impersonation_bank_govt", "impersonation", 15, (
        r"\b(?:sbi|hdfc|icici|axis bank|pnb|punjab national|bank of baroda|canara|kotak|paytm|phonepe|google ?pay|gpay|npci|rbi|income ?tax|uidai|trai|epfo|electricity board|pspcl|dhbvn|uhbvn|bescom|courier|fedex|dhl|india post|customs)\b",
        r"(?:भारतीय स्टेट बैंक|स्टेट बैंक|आयकर|आधार|पंजाब नेशनल|बिजली विभाग|दूरसंचार|कूरियर)",
        r"(?:ਸਟੇਟ ਬੈਂਕ|ਆਧਾਰ|ਬਿਜਲੀ ਵਿਭਾਗ|ਕੋਰੀਅਰ)",
    )),
    Rule("parcel_courier", "parcel", 25, (
        r"\b(?:parcel|package|shipment|consignment)\b.{0,80}(?:held|seized|stuck|returned|undelivered|customs|illegal|drugs|fee|pay|address)",
        r"(?:पार्सल|कूरियर).{0,60}(?:रोक|जब्त|फंस|अवैध|फीस|भुगतान)",
        r"(?:ਪਾਰਸਲ|ਕੋਰੀਅਰ).{0,60}(?:ਰੋਕ|ਜ਼ਬਤ|ਫੀਸ)",
    )),
    Rule("electricity_disconnect", "electricity", 30, (
        r"(?:electricity|power|bijli|बिजली|ਬਿਜਲੀ).{0,50}(?:bill|बिल|ਬਿੱਲ).{0,60}(?:tonight|today|9:?30|disconnect|cut|कट|ਕੱਟ|अपडेट|update)",
        r"(?:electricity|power|bijli|बिजली|ਬਿਜਲੀ).{0,60}(?:disconnect(?:ed)?|cut|kat(?:t)?|कट|ਕੱਟ).{0,80}(?:bill|बिल|ਬਿੱਲ|update|अपडेट|ਅਪਡੇਟ|pay|tonight|today)",
    )),
    Rule("sextortion_threat", "extortion", 40, (
        r"\b(?:your (?:video|photos?|pictures?)|private (?:video|photos?)).{0,60}(?:viral|leak|share|post|send to (?:your )?(?:family|contacts|friends))\b",
        r"(?:वीडियो|फोटो).{0,40}(?:वायरल|लीक).{0,40}(?:पैसे|पेमेंट|रुपये)",
    )),
    Rule("suspicious_link_bait", "link_bait", 20, (
        r"(?:click|tap|open|visit|login|log in|download|install|खोलें|क्लिक|दबाएं|ਕਲਿੱਕ).{0,40}(?:link|below|here|http|bit\.ly|tinyurl|लिंक|ਲਿੰਕ)",
        r"\b(?:link|लिंक|ਲਿੰਕ)\b.{0,40}(?:click|tap|open|क्लिक|खोलें|दबाएं|ਕਲਿੱਕ)",
    )),
)

# Phrases found in genuine bank warnings: they tell people NOT to share secrets.
PROTECTIVE_PATTERNS: tuple[str, ...] = (
    r"(?:do not|don't|never|dont|kisi se|किसी से).{0,30}(?:share|disclose|tell|batayen|बताएं|साझा|न बताएं|ਨਾ ਦੱਸੋ).{0,40}(?:otp|pin|cvv|password|ओटीपी|पिन)",
    r"(?:otp|ओटीपी|ਓਟੀਪੀ|pin|पिन|cvv).{0,60}(?:किसी (?:को|से)|किसी और).{0,15}(?:न|ना|मत|नहीं)\s*(?:बता|दें|दे|साझा|शेयर)",
    r"(?:otp|ओटीपी|ਓਟੀਪੀ|pin|ਪਿੰਨ).{0,60}ਕਿਸੇ (?:ਨੂੰ|ਨਾਲ).{0,15}(?:ਨਾ|ਨਹੀਂ)\s*(?:ਦੱਸੋ|ਦਿਓ|ਸਾਂਝਾ)",
    r"(?:otp|pin).{0,60}(?:kisi ko|kisi se).{0,15}(?:na|mat|nahi)\s*(?:bata|bhej|de|share)",
    r"(?:bank|sbi|hdfc|icici|never|कभी नहीं).{0,40}(?:never|कभी नहीं|will not|won't).{0,30}(?:ask|माँगता|मांगता|पूछता)",
    r"\b(?:is|का|ਦਾ) ?(?:your|आपका|ਤੁਹਾਡਾ)? ?(?:otp|one time password)\b.{0,40}(?:valid|expires?|वैध)",
    r"\botp (?:is|for)\b.{0,10}\d{4,8}\b",
)


_COMPILED: list[tuple[Rule, list[re.Pattern[str]]]] = [
    (rule, [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.patterns]) for rule in RULES
]
_PROTECTIVE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in PROTECTIVE_PATTERNS]

# Combos: more than the sum of their parts.
_COMBO_BONUS = (
    ({"kyc", "block_threat"}, 15),
    ({"kyc", "link_bait"}, 15),
    ({"block_threat", "link_bait"}, 15),
    ({"urgency", "otp"}, 10),
    ({"urgency", "pin"}, 10),
    ({"impersonation", "kyc"}, 10),
    ({"impersonation", "block_threat"}, 10),
    ({"lottery", "advance_fee"}, 15),
    ({"lottery", "link_bait"}, 10),
    ({"legal_threat", "urgency"}, 10),
    ({"parcel", "advance_fee"}, 10),
)


_ASK_RE = re.compile(_ASK, re.IGNORECASE)
# A negator shortly before a verb: "do not share", "never tell", "किसी को न बताएं", "ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ".
_NEG_RE = re.compile(
    r"(?:\b(?:do not|don't|dont|never|not|cannot|can't|nobody|no one|without)\b|(?<![\w\u0900-\u097F\u0A00-\u0A7F])(?:न|ना|मत|नहीं|ਨਾ|ਨਹੀਂ|ਨਾਂ|na|mat|nahi|nahin)(?![\w\u0900-\u097F\u0A00-\u0A7F]))"
    r"(?:[ \t]+[^\W_]+){0,2}[ \t]*$",
    re.IGNORECASE,
)
_NEGATION_SENSITIVE = {"ask_otp", "ask_pin", "ask_password"}


def _is_only_negated_asks(norm: str, m: re.Match[str]) -> bool:
    """True when every 'send/share/tell' verb in the match is negated ("do not share your OTP")."""
    start = max(0, m.start() - 24)
    window = norm[start : m.end()]
    verbs = list(_ASK_RE.finditer(window))
    if not verbs:
        return False
    for v in verbs:
        prefix = window[max(0, v.start() - 24) : v.start()]
        if not _NEG_RE.search(prefix):
            return False
    return True


def evaluate(text: str) -> RuleResult:
    """Score `text` from 0 to 100 and report which patterns fired."""
    norm = normalise(text)
    if not norm:
        return RuleResult(score=0)

    hits: list[RuleHit] = []
    for rule, patterns in _COMPILED:
        for pat in patterns:
            m = pat.search(norm)
            if not m:
                continue
            if rule.id in _NEGATION_SENSITIVE and _is_only_negated_asks(norm, m):
                continue  # "never share your OTP" is advice, not a request
            hits.append(RuleHit(rule.id, rule.category, rule.weight, m.group(0)[:80]))
            break

    categories = [h.category for h in hits]
    cat_set = set(categories)
    score = sum(h.weight for h in hits)

    for needed, bonus in _COMBO_BONUS:
        if needed <= cat_set:
            score += bonus

    # Impersonation alone (a bank name) is not suspicious; it only matters with another signal.
    if cat_set == {"impersonation"}:
        score = 0

    protective = any(p.search(norm) for p in _PROTECTIVE)
    # Genuine OTP/"never share" notices: only discount when nothing asks for a secret.
    asks_secret = bool(cat_set & {"pin", "credentials"}) or any(
        h.rule_id == "ask_otp" for h in hits
    )
    if protective and not (cat_set & {"lottery", "advance_fee", "remote_access", "malware", "legal_threat"}):
        if not any(h.rule_id in {"ask_pin", "ask_password"} for h in hits):
            score = int(score * 0.35) if asks_secret else int(score * 0.5)

    return RuleResult(score=max(0, min(100, score)), hits=hits, categories=sorted(cat_set), protective=protective)
