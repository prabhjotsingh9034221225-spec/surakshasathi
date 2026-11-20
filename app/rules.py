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
    text = re.sub("[\u200b\u200c\u200d\u2060\ufeff\u00ad]", "", text)  # invisible characters used to split keywords
    text = text.lower()
    return re.sub(r"\s+", " ", text).strip()


_LEET = str.maketrans({"@": "a", "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
_SPACED = re.compile(r"\b(?:[a-z][ .\-_*]){2,}[a-z]\b")


def _deleet(norm: str) -> str:
    """'0TP', 'Y0ur b@nk', '1mm3d1@t3ly' -> 'otp', 'your bank', 'immediately'. Only touches words that mix letters and symbols."""
    out = []
    for tok in norm.split(" "):
        if "://" in tok or tok.startswith("www.") or not re.search(r"[a-z]", tok) or not re.search(r"[@0134579$]", tok):
            out.append(tok)
        else:
            out.append(tok.translate(_LEET))
    return " ".join(out)


def variants(text: str) -> list[str]:
    """The text as written, plus de-obfuscated copies, so tricks like O.T.P, 0TP or !!!-padding do not hide a scam."""
    norm = normalise(text)
    if not norm:
        return []
    cands = [
        norm,
        _deleet(norm),
        _SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), norm),
        re.sub(r"[!*#~^]{2,}", ".", norm),
    ]
    cands.append(_SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), _deleet(norm)))
    seen: list[str] = []
    for c in cands:
        if c not in seen:
            seen.append(c)
    return seen


# Words meaning "send / share / tell / give" across the supported languages.
_ASK = (
    r"(?<![a-z])(?:send|share|tell|give|provide|enter|submit|forward|confirm|reply|bata(?:o|iye|na)?|bhej(?:o|iye|na)?|"
    r"de(?:do|na|iye)?|dijiye|batao|bolo|dasso|dass|bhejo|shere?|साझा|बताएं|बताओ|बताइए|भेजें|भेजो|दें|दीजिए|दो|"
    r"बताओ|भेजिए|ਦੱਸੋ|ਦੱਸ|ਭੇਜੋ|ਦਿਓ|ਸਾਂਝਾ)(?![a-z])"
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
    # Account takeover: "I sent my code to your number by mistake" / "verify by sharing the SMS code".
    Rule("whatsapp_code", "otp", 62, (
        r"\b(?:6|six)[- ]?digit (?:code|number|otp)\b.{0,80}(?:forward|send|share|give|tell|back)",
        r"(?:sent|send|sms|received).{0,40}\b(?:code|otp)\b.{0,60}(?:by mistake|accident|forward (?:it )?(?:to me|back)|send (?:it )?(?:to me|back))",
        r"(?:verify|verification|activate|deactivat|secure).{0,60}(?:sharing|share|send|forward|reply with|tell).{0,30}\b(?:the )?(?:code|otp)\b",
        r"\b(?:whatsapp|telegram)\b.{0,60}(?:deactivat|suspend|ban|block|expire).{0,80}\b(?:code|otp|verify)\b",
    )),
    Rule("qr_receive", "upi_collect", 58, (
        r"\bqr\b.{0,60}(?:receive|get|cashback|refund|reward|prize|credit).{0,60}(?:pin|scan|enter)",
        r"\b(?:scan|scanning)\b.{0,30}\bqr\b.{0,80}(?:receive|get|cashback|refund|reward|prize|credit|pin)",
        r"\bqr\b.{0,40}(?:scan|karo|kare|करो).{0,40}(?:pin|पिन)",
        r"(?:cashback|refund|inaam|reward).{0,40}\bqr\b.{0,40}(?:scan|pin)",
        r"(?:क्यूआर|क्यू आर).{0,40}(?:स्कैन|पिन)",
    )),
    Rule("govt_benefit_bait", "kyc", 55, (
        r"\b(?:income ?tax|it dept|itr)\b.{0,30}\brefund\b(?!.{0,80}\b(?:credited|processed|initiated|issued)\b)",
        r"\b(?:refund|subsidy|scheme|yojana|benefit|installment|instalment|kisan|pension)\b.{0,60}(?:pending|approved|credited|aane wala|ready|released).{0,100}(?:bank detail|account detail|link|otp|click|update|submit|claim|receive)",
        r"\b(?:bank detail|account detail|aadhaar|pan)\b.{0,60}(?:to receive|to get|to claim|receive (?:it|the|your)|claim (?:it|the|your))",
        r"\be-?challan\b.{0,80}(?:pay|fine|pending|legal|link|http)",
        r"\bfastag\b.{0,60}(?:kyc|block|expire|update|suspend)",
        r"\b(?:sim|mobile number|number)\b.{0,40}(?:blocked|disconnected|deactivated|suspended).{0,60}(?:call|press|kyc|verify)",
        r"\btrai\b.{0,80}(?:disconnect|illegal|block|notice|press \d)",
        r"\baadhaar\b.{0,60}(?:deactivat|suspend|block|cancel|expire)",
        r"(?:आधार|पैन).{0,40}(?:बंद|ब्लॉक|रद्द|निष्क्रिय)",
        r"(?:पीएम किसान|किसान).{0,40}(?:पैसा|राशि|किस्त).{0,60}(?:otp|बैंक|लिंक)",
    )),
    Rule("account_verify_bait", "kyc", 40, (
        r"\b(?:verify|update|confirm|renew|re-?activate)\b.{0,30}\b(?:payment|billing|account|login|card)\b.{0,80}(?:https?://|www\.|\.(?:xyz|top|click|site|online|cc|info|icu)\b|\blink\b)",
        r"\b(?:subscription|membership|account)\b.{0,40}\b(?:suspended|expired|closed|cancelled|blocked)\b.{0,80}(?:https?://|www\.|\blink\b)",
        r"\b(?:or|otherwise)\b.{0,30}\b(?:closed|suspended|blocked|deactivated)\b.{0,40}\b(?:permanently|forever)\b",
    )),
    Rule("loan_bait", "advance_fee", 32, (
        r"\b(?:instant|quick|pre-?approved)?\s?loan\b.{0,60}(?:approved|sanctioned|without (?:documents|cibil|collateral)|no documents)",
        r"\bloan\b.{0,80}(?:processing fee|insurance|registration|advance|pay rs|pay ₹)",
        r"(?:लोन|कर्ज).{0,40}(?:मंजूर|पास|बिना दस्तावेज).{0,60}(?:फीस|शुल्क|जमा)",
    )),
    Rule("task_deposit", "job_scam", 40, (
        r"\b(?:deposit|pay|recharge|invest)\b.{0,40}(?:rs\.?|₹|inr)?\s?\d[\d,]*.{0,60}(?:to start|to begin|to unlock|get it back|commission|id card|uniform|training|task)",
        r"\b(?:per task|each task|every task|daily task|task job|subscribe and earn|like (?:and|&) subscribe)\b",
        r"\bselected for\b.{0,60}(?:work from home|job|hiring).{0,80}(?:pay|fee|deposit|rs\.?|₹)",
    )),
    Rule("secrecy_pressure", "urgency", 25, (
        r"\b(?:do not|don't|dont|never|mat|nahi)\b.{0,15}\b(?:tell|inform|batana|bataana|batao)\b.{0,25}\b(?:anyone|anybody|family|police|bank|kisi ko|kisi se|ghar)",
        r"\bkisi ko (?:mat|na|nahi) (?:batana|batao|bataana|batayen)\b",
        r"\b(?:keep (?:this|it) (?:a )?secret|this is confidential)\b",
        r"(?:किसी को (?:मत|न|नहीं) (?:बताना|बताएं|बताओ))",
        r"(?:ਕਿਸੇ ਨੂੰ (?:ਨਾ|ਨਹੀਂ) (?:ਦੱਸੋ|ਦੱਸਣਾ))",
    )),
    Rule("police_hinglish", "legal_threat", 60, (
        r"\b(?:police|cbi|crime branch|cyber cell|ed)\b.{0,30}\b(?:se bol|bol raha|bol rahi|speaking|calling).{0,120}(?:giraftar|arrest|case|fir|paise|pay|transfer|jail)",
        r"\b(?:giraftari|giraftar)\b.{0,60}(?:paise|pay|transfer|bhej|fine|warna)",
        r"(?:paise|payment|fine|bhej).{0,40}\bwarna\b.{0,40}(?:giraftar|arrest|jail|case|fir)",
        r"(?:ed|cbi|police) (?:officer|inspector).{0,100}(?:money laundering|illegal|case|warrant)",
        r"(?:money laundering|illegal activit).{0,100}(?:do not disconnect|stay on|do not tell|aadhaar)",
        r"\bpress \d\b.{0,40}(?:officer|executive|customer care)",
    )),
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
        r"\b(?:fedex|dhl|courier|parcel|package)\b.{0,100}\b(?:drugs|narcotics|illegal|cyber ?crime|mumbai crime)\b",
        r"(?:ਗ੍ਰਿਫ਼ਤਾਰੀ|ਪੁਲਿਸ).{0,60}(?:ਪੈਸੇ|ਜੁਰਮਾਨਾ)",
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
        r"\breward points?\b.{0,20}(?:expire|redeem).{0,80}(?:https?://|www\.|\blink\b|today|tonight|now|\bworth\b)",
        r"(?:लॉटरी|लकी ड्रा).{0,60}(?:जीत|इनाम|निकली|करोड़|लाख|जमा)",
        r"(?:जीत|इनाम).{0,60}(?:लॉटरी|लकी ड्रा)",
        r"(?:ਲਾਟਰੀ|ਇਨਾਮ).{0,60}(?:ਜਿੱਤ|ਇਨਾਮ|ਲੱਖ|ਕਰੋੜ)",
        r"(?:ਜਿੱਤ|ਜਿੱਤੀ).{0,60}(?:ਲਾਟਰੀ|ਇਨਾਮ)",
        r"(?:ਇਨਾਮ|ਲਾਟਰੀ).{0,50}(?:ਲੱਗਿਆ|ਲੱਗੀ|ਨਿਕਲਿਆ|ਨਿਕਲੀ|ਮਿਲਿਆ)",
        r"(?:iphone|laptop|car|bike|gift)\b.{0,40}(?:lucky draw|won|winner|selected).{0,80}(?:pay|delivery charge|charges|fee)",
        r"\blucky (?:draw|winner)\b.{0,80}(?:pay|fee|charge|claim)",
        r"\b(?:inaam|inam)\b.{0,40}\b(?:jeet|jita|jeeta|mila|nikla)\b",
        r"\blottery (?:nikli|nikla|lagi)\b",
    )),
    Rule("advance_fee", "advance_fee", 35, (
        r"\b(?:processing fee|registration fee|release fee|claim fee|customs fee|clearance fee|insurance fee|gst fee|tax to claim)\b",
        r"(?:pay|deposit|transfer|send).{0,30}(?:₹|rs\.?|inr)\s?\d[\d,]*.{0,40}(?:to (?:claim|receive|release|get|unlock)|fee|charges)",
        r"(?:प्रोसेसिंग फीस|रजिस्ट्रेशन फीस|चार्ज जमा|फीस जमा)",
        r"(?:ਪ੍ਰੋਸੈਸਿੰਗ ਫੀਸ|ਫੀਸ ਜਮ੍ਹਾ)",
        r"(?:ਟੈਕਸ|ਫੀਸ|ਚਾਰਜ).{0,30}(?:ਭਰਨ|ਭਰੋ|ਜਮ੍ਹਾ).{0,40}(?:ਪੈਸੇ|ਰੁਪਏ|ਭੇਜੋ)",
        r"\b(?:delivery charge|redelivery fee|re-?delivery|shipping charge|handling fee|verification fee|activation fee)s?\b.{0,60}(?:rs\.?|₹|pay|\d)",
        r"\bpay (?:rs\.?|₹)\s?\d{1,3}\b.{0,40}(?:verify|kyc|avoid|suspension|activate)",
    )),
    Rule("job_scam", "job_scam", 30, (
        r"\b(?:work from home|part[- ]time job|earn (?:₹|rs\.?)?\s?\d[\d,]*\s?(?:per|/)\s?(?:day|hour|week)|task (?:job|based)|like (?:and|&) (?:earn|subscribe)|youtube like|data entry job)\b",
        r"(?:घर बैठे कमाएं|पार्ट टाइम जॉब|रोज़ कमाएं|रोज कमाएं)",
        r"(?:ਘਰ ਬੈਠੇ ਕਮਾਓ|ਪਾਰਟ ਟਾਈਮ ਨੌਕਰੀ)",
        r"\bearn (?:rs\.?|₹)?\s?\d[\d,]*\s?(?:per|/|a) ?(?:task|video|like|click)",
        r"\b(?:work from home|wfh)\b.{0,80}(?:salary|earn|income)",
    )),
    Rule("investment_scam", "investment", 60, (
        r"\b(?:guaranteed returns?|double your (?:money|investment)|100% (?:profit|return)|crypto (?:giveaway|trading tips)|stock tips? (?:group|vip)|ipo allotment guaranteed|risk[- ]free profit)\b",
        r"\b(?:\d{2,4}% (?:profit|returns?)|profit guaranteed|guaranteed profit|daily returns?|daily profit|(?:vip|premium) (?:trading|stock|crypto) (?:group|tips|signals?))\b",
        r"\b(?:bitcoin|crypto|forex|trading)\b.{0,80}(?:daily|guaranteed|returns?|profit).{0,80}(?:telegram|whatsapp|contact|manager|join|invest)",
        r"\binvest\b.{0,40}(?:rs\.?|₹)\s?[\d,]+.{0,60}(?:withdraw|get back|receive|returns?).{0,30}(?:rs\.?|₹)?\s?[\d,]+",
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
        r"\b(?:transfer|send|pay)\b.{0,40}(?:rs\.?|₹)\s?[\d,]+.{0,80}(?:will return|will pay back|return tomorrow|emergency|urgent).{0,60}(?:don'?t call|do not call|dont call|kisi ko mat)",
        r"\b(?:mom|mum|mummy|dad|papa|beta|bhai|bhaiya|uncle|aunty)\b.{0,100}(?:new number|naya number|lost my phone|phone kho gaya).{0,120}(?:send|transfer|bhej|pay)",
        r"(?:new|naya|nayi|naye|नया|नई|ਨਵਾਂ|ਨਵੀਂ).{0,25}(?:number|no\.?|नंबर|ਨੰਬਰ).{0,120}(?:send|transfer|bhejo|bhej do|bhej de|भेजो|भेज दो|ਭੇਜੋ|pay|paytm|gpay|phonepe)",
        r"(?:mummy|mom|mum|papa|dad|beta|bhaiya|मम्मी|पापा|बेटा|ਮੰਮੀ|ਪਾਪਾ).{0,40}(?:phone|mobile|फोन|ਫੋਨ).{0,30}(?:kharab|broke|lost|खराब|खो|ਖਰਾਬ|ਗੁੰਮ).{0,120}(?:send|bhejo|भेजो|ਭੇਜੋ|transfer|pay)",
    )),
    Rule("stranded_relative", "family_impersonation", 58, (
        r"\b(?:stuck|stranded)\b.{0,20}\babroad\b.{0,160}(?:send|transfer|pay|upi|account|money)",
        r"\b(?:lost|stolen) (?:my )?(?:wallet|phone|passport|bag)\b.{0,140}(?:send|transfer|pay|upi|account)",
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
    Rule("electricity_disconnect", "electricity", 42, (
        r"(?:electricity|power|bijli|बिजली|ਬਿਜਲੀ).{0,60}(?:unpaid|overdue|pending|not (?:been )?paid|bill).{0,80}(?:cut|disconnect|tonight|today).{0,80}(?:officer|call|contact|helpline|\d{8,})",
        r"\bbijli\b.{0,60}\b(?:kat|katt|cut|band)\b",
        r"(?:electricity|power|bijli|बिजली|ਬਿਜਲੀ).{0,50}(?:bill|बिल|ਬਿੱਲ).{0,60}(?:tonight|today|9:?30|disconnect|cut|कट|ਕੱਟ|अपडेट|update)",
        r"(?:electricity|power|bijli|बिजली|ਬਿਜਲੀ).{0,60}(?:disconnect(?:ed)?|cut|kat(?:t)?|कट|ਕੱਟ).{0,80}(?:bill|बिल|ਬਿੱਲ|update|अपडेट|ਅਪਡੇਟ|pay|tonight|today)",
    )),
    Rule("sextortion_threat", "extortion", 62, (
        r"\b(?:private|intimate|nude|your) (?:video|videos|photos?|pictures?|clips?)\b.{0,100}(?:pay|send|transfer).{0,100}(?:contacts|family|friends|everyone|viral|social media|leak)",
        r"\b(?:pay|send|transfer)\b.{0,60}(?:or|otherwise|else|warna)\b.{0,60}(?:send|share|post|upload|leak|viral).{0,40}(?:video|photos?|contacts|family|friends)",
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
    r"\bno action (?:is )?(?:needed|required)\b",
    r"\bonly if\b.{0,40}\b(?:unpaid|overdue|not paid|remains)\b|\b(?:beyond|after|before) the due date\b",
    r"\bappointment\b.{0,60}\b(?:confirmed|scheduled)\b|\bconfirmed for\b",
    r"\b(?:has been|have been|was|were)\s+(?:successfully\s+)?(?:credited|processed|initiated|generated|delivered|dispatched|booked|confirmed|received|allotted|debited)\b",
    r"\botp\b.{0,30}\bis\b\s*\d{4,8}\b",
    r"\b(?:at|in) (?:the|our|your) (?:store|showroom|branch|office|counter|clinic|school)\b|\bin[- ]store\b|\bvisit (?:the|our|your)(?: nearest)? (?:store|showroom|branch|office)\b",
)


_COMPILED: list[tuple[Rule, list[re.Pattern[str]]]] = [
    (rule, [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.patterns]) for rule in RULES
]
_OFFICIAL_CHANNEL = re.compile(
    r"\b(?:on|via|through|at|only on|only at) the official (?:\w+ )?(?:app|portal|website|site)\b|\bofficial (?:uidai|passport|parivahan|epfo|irctc|icegate|lic|bank|municipal) (?:website|portal|app)\b|"
    r"\bnumber on the back of (?:your|the) card\b|\bblock the card in the (?:bank )?app\b|\bofficial \w+ portal\b",
    re.IGNORECASE,
)
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
_ADVICE_RE = re.compile(r"\b(?:do not|don[’']?t|dont|never)\s+(?:share|tell|give|send|forward|disclose)\b", re.IGNORECASE)
_NEGATION_SENSITIVE = {"ask_otp", "ask_pin", "ask_password", "whatsapp_code"}


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
    texts = variants(text)
    if not texts:
        return RuleResult(score=0)
    norm = texts[0]

    hits: list[RuleHit] = []
    for rule, patterns in _COMPILED:
        found = False
        for variant in texts:  # the text as written first, then de-obfuscated copies
            for pat in patterns:
                m = pat.search(variant)
                if not m:
                    continue
                if rule.id in _NEGATION_SENSITIVE and _is_only_negated_asks(variant, m):
                    continue  # "never share your OTP" is advice, not a request
                if rule.id == "whatsapp_code" and _ADVICE_RE.search(variant[max(0, m.start() - 20) : m.end() + 20]):
                    continue  # "Don't share this code with anyone" is a genuine notice
                hits.append(RuleHit(rule.id, rule.category, rule.weight, m.group(0)[:80]))
                found = True
                break
            if found:
                break

    # Intent layer: the same ingredients in different words (catches scams nobody has written a rule for yet).
    from . import intent

    best_intent = max((intent.score(v) for v in texts), key=lambda r: r.score)
    if best_intent.category and best_intent.score >= 40 and not any(h.category == best_intent.category and h.weight >= best_intent.score for h in hits):
        hits.append(RuleHit("intent", best_intent.category, best_intent.score, (best_intent.reason or "")[:80]))

    categories = [h.category for h in hits]
    cat_set = set(categories)
    score = sum(h.weight for h in hits)

    for needed, bonus in _COMBO_BONUS:
        if needed <= cat_set:
            score += bonus

    # Impersonation alone (a bank name) is not suspicious; it only matters with another signal.
    if cat_set == {"impersonation"}:
        score = 0

    protective = any(p.search(v) for v in texts for p in _PROTECTIVE) or (
        bool(_OFFICIAL_CHANNEL.search(norm)) and not re.search(r"https?://|www\.|\.(?:top|click|xyz|site|icu)\b", norm)
    )
    # Genuine OTP/"never share" notices: only discount when nothing asks for a secret.
    asks_secret = bool(cat_set & {"pin", "credentials"}) or any(
        h.rule_id == "ask_otp" for h in hits
    )
    official_only = bool(_OFFICIAL_CHANNEL.search(norm)) and not re.search(r"https?://|www\.|[6-9]\d{9}", norm)
    if official_only and not any(h.rule_id in {"ask_pin", "ask_password"} for h in hits):
        score = int(score * 0.4)
    elif protective and not (cat_set & {"lottery", "advance_fee", "remote_access", "malware", "legal_threat"}):
        if not any(h.rule_id in {"ask_pin", "ask_password"} for h in hits):
            score = int(score * 0.35) if asks_secret else int(score * 0.5)

    return RuleResult(score=max(0, min(100, score)), hits=hits, categories=sorted(cat_set), protective=protective)
