"""Language detection and all user-facing text in English, Hindi and Punjabi."""
from __future__ import annotations

import re

SUPPORTED = ("en", "hi", "pa")
LANG_LABELS = {"en": "English", "hi": "हिन्दी", "pa": "ਪੰਜਾਬੀ"}

_DEVANAGARI = re.compile(r"[ऀ-ॿ]")
_GURMUKHI = re.compile(r"[਀-੿]")
_HINGLISH_WORDS = re.compile(
    r"\b(?:aap|apka|aapka|apna|hai|hain|nahi|nahin|kripya|kya|kyun|kaise|bhejo|bhej|batao|bata|turant|jaldi|khata|paise|paisa|"
    r"band|ho jayega|jaega|karein|kare|karo|dalo|daalo|abhi|sir|madam|ji|aapke|aapko|mera|meri|inaam|bijli|rupaye|rupay)\b",
    re.IGNORECASE,
)
_PUNJABI_ROMAN = re.compile(
    r"\b(?:tusi|tuhada|tuhanu|tuhade|sade|dasso|dass|karo ji|hunne|kithe|ki haal|sat sri akal|paaji|veer|bai ji|"
    r"tuhadi|kar dita|ho gya|hoyi|haige|hega|chahida)\b",
    re.IGNORECASE,
)


def detect_language(text: str, default: str = "en") -> str:
    if not text:
        return default
    gur = len(_GURMUKHI.findall(text))
    dev = len(_DEVANAGARI.findall(text))
    if gur > dev and gur >= 3:
        return "pa"
    if dev >= 3:
        return "hi"
    if _PUNJABI_ROMAN.search(text):
        return "pa"
    if len(_HINGLISH_WORDS.findall(text)) >= 2:
        return "hi"
    return default


# --- verdict labels --------------------------------------------------------
VERDICT_HEAD = {
    "scam": {
        "en": "🚨 This is a SCAM. Do not click, do not reply, do not pay.",
        "hi": "🚨 यह ठगी (स्कैम) है! न लिंक खोलें, न जवाब दें, न पैसे भेजें।",
        "pa": "🚨 ਇਹ ਠੱਗੀ (ਸਕੈਮ) ਹੈ! ਨਾ ਲਿੰਕ ਖੋਲ੍ਹੋ, ਨਾ ਜਵਾਬ ਦਿਓ, ਨਾ ਪੈਸੇ ਭੇਜੋ।",
    },
    "suspicious": {
        "en": "⚠️ This looks SUSPICIOUS. Be careful, and check with someone you trust before doing anything.",
        "hi": "⚠️ यह संदिग्ध लग रहा है। कुछ भी करने से पहले किसी भरोसेमंद व्यक्ति से पूछ लें।",
        "pa": "⚠️ ਇਹ ਸ਼ੱਕੀ ਲੱਗਦਾ ਹੈ। ਕੁਝ ਵੀ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਕਿਸੇ ਭਰੋਸੇਮੰਦ ਬੰਦੇ ਤੋਂ ਪੁੱਛ ਲਓ।",
    },
    "safe": {
        "en": "✅ This looks SAFE. Still, never share your OTP or PIN with anyone.",
        "hi": "✅ यह सुरक्षित लग रहा है। फिर भी OTP या PIN किसी को न बताएं।",
        "pa": "✅ ਇਹ ਸੁਰੱਖਿਅਤ ਲੱਗਦਾ ਹੈ। ਫਿਰ ਵੀ OTP ਜਾਂ PIN ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ।",
    },
}

# --- one-line reasons per detected category (first matching category wins by priority) ---
REASONS = {
    "pin": {
        "en": "Someone is asking for your PIN or card details. A real bank or UPI app NEVER asks for this.",
        "hi": "कोई आपका PIN या कार्ड की जानकारी मांग रहा है। असली बैंक या UPI ऐप कभी नहीं मांगता।",
        "pa": "ਕੋਈ ਤੁਹਾਡਾ PIN ਜਾਂ ਕਾਰਡ ਦੀ ਜਾਣਕਾਰੀ ਮੰਗ ਰਿਹਾ ਹੈ। ਅਸਲੀ ਬੈਂਕ ਜਾਂ UPI ਐਪ ਕਦੇ ਨਹੀਂ ਮੰਗਦਾ।",
    },
    "otp": {
        "en": "Someone is asking for your OTP. A real bank NEVER asks for your OTP.",
        "hi": "कोई आपका OTP मांग रहा है। असली बैंक कभी OTP नहीं मांगता।",
        "pa": "ਕੋਈ ਤੁਹਾਡਾ OTP ਮੰਗ ਰਿਹਾ ਹੈ। ਅਸਲੀ ਬੈਂਕ ਕਦੇ OTP ਨਹੀਂ ਮੰਗਦਾ।",
    },
    "upi_collect": {
        "en": "Receiving money never needs your PIN. Approving this request will take money OUT of your account.",
        "hi": "पैसे पाने के लिए PIN की जरूरत नहीं होती। इसे मंजूर करने पर आपके खाते से पैसे कट जाएंगे।",
        "pa": "ਪੈਸੇ ਲੈਣ ਲਈ PIN ਦੀ ਲੋੜ ਨਹੀਂ ਹੁੰਦੀ। ਇਸ ਨੂੰ ਮਨਜ਼ੂਰ ਕਰਨ ਨਾਲ ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚੋਂ ਪੈਸੇ ਕੱਟ ਜਾਣਗੇ।",
    },
    "remote_access": {
        "en": "They want you to install a screen-sharing app. Scammers use it to see your phone and empty your bank account.",
        "hi": "आपसे स्क्रीन-शेयरिंग ऐप डालने को कहा जा रहा है। ठग इससे आपका फोन देखकर खाता खाली कर देते हैं।",
        "pa": "ਤੁਹਾਨੂੰ ਸਕ੍ਰੀਨ-ਸ਼ੇਅਰਿੰਗ ਐਪ ਪਾਉਣ ਲਈ ਕਿਹਾ ਜਾ ਰਿਹਾ ਹੈ। ਠੱਗ ਇਸ ਨਾਲ ਤੁਹਾਡਾ ਫੋਨ ਵੇਖ ਕੇ ਖਾਤਾ ਖਾਲੀ ਕਰ ਦਿੰਦੇ ਹਨ।",
    },
    "malware": {
        "en": "This asks you to install an app file (APK) from a link. It can steal your money and messages.",
        "hi": "यह लिंक से APK ऐप डालने को कहता है। इससे आपके पैसे और मैसेज चोरी हो सकते हैं।",
        "pa": "ਇਹ ਲਿੰਕ ਤੋਂ APK ਐਪ ਪਾਉਣ ਲਈ ਕਹਿੰਦਾ ਹੈ। ਇਸ ਨਾਲ ਤੁਹਾਡੇ ਪੈਸੇ ਅਤੇ ਮੈਸੇਜ ਚੋਰੀ ਹੋ ਸਕਦੇ ਹਨ।",
    },
    "legal_threat": {
        "en": "Police and courts never arrest people over phone or video calls or ask for money. This is a 'digital arrest' scam.",
        "hi": "पुलिस या कोर्ट फोन/वीडियो कॉल पर गिरफ्तारी या पैसे की मांग नहीं करते। यह 'डिजिटल अरेस्ट' ठगी है।",
        "pa": "ਪੁਲਿਸ ਜਾਂ ਕੋਰਟ ਫੋਨ/ਵੀਡੀਓ ਕਾਲ ਤੇ ਗ੍ਰਿਫ਼ਤਾਰੀ ਜਾਂ ਪੈਸੇ ਦੀ ਮੰਗ ਨਹੀਂ ਕਰਦੇ। ਇਹ 'ਡਿਜੀਟਲ ਅਰੈਸਟ' ਠੱਗੀ ਹੈ।",
    },
    "extortion": {
        "en": "This is blackmail. Do not pay. Save the proof and report it.",
        "hi": "यह ब्लैकमेल है। पैसे न दें। सबूत रखें और शिकायत करें।",
        "pa": "ਇਹ ਬਲੈਕਮੇਲ ਹੈ। ਪੈਸੇ ਨਾ ਦਿਓ। ਸਬੂਤ ਰੱਖੋ ਅਤੇ ਸ਼ਿਕਾਇਤ ਕਰੋ।",
    },
    "kyc": {
        "en": "Banks never ask you to update KYC through a link, call or message. This is a common phishing trick.",
        "hi": "बैंक KYC अपडेट के लिए लिंक, कॉल या मैसेज नहीं भेजते। यह ठगी का आम तरीका है।",
        "pa": "ਬੈਂਕ KYC ਅਪਡੇਟ ਲਈ ਲਿੰਕ, ਕਾਲ ਜਾਂ ਮੈਸੇਜ ਨਹੀਂ ਭੇਜਦੇ। ਇਹ ਠੱਗੀ ਦਾ ਆਮ ਤਰੀਕਾ ਹੈ।",
    },
    "lottery": {
        "en": "You cannot win a lottery or prize you never entered. Prize messages that ask for a fee are always fake.",
        "hi": "जिस लॉटरी में आपने हिस्सा ही नहीं लिया, उसमें इनाम नहीं मिलता। फीस मांगने वाले इनाम हमेशा नकली होते हैं।",
        "pa": "ਜਿਸ ਲਾਟਰੀ ਵਿੱਚ ਤੁਸੀਂ ਹਿੱਸਾ ਹੀ ਨਹੀਂ ਲਿਆ, ਉਸ ਵਿੱਚ ਇਨਾਮ ਨਹੀਂ ਮਿਲਦਾ। ਫੀਸ ਮੰਗਣ ਵਾਲੇ ਇਨਾਮ ਹਮੇਸ਼ਾ ਨਕਲੀ ਹੁੰਦੇ ਹਨ।",
    },
    "advance_fee": {
        "en": "They ask you to pay a fee first to get money or a prize. That is the trick: the prize never comes.",
        "hi": "पैसे या इनाम पाने के लिए पहले फीस मांगी जा रही है। यही ठगी है, इनाम कभी नहीं आता।",
        "pa": "ਪੈਸੇ ਜਾਂ ਇਨਾਮ ਲੈਣ ਲਈ ਪਹਿਲਾਂ ਫੀਸ ਮੰਗੀ ਜਾ ਰਹੀ ਹੈ। ਇਹੀ ਠੱਗੀ ਹੈ, ਇਨਾਮ ਕਦੇ ਨਹੀਂ ਆਉਂਦਾ।",
    },
    "electricity": {
        "en": "The electricity board does not cut power over a WhatsApp or SMS message asking you to call a number.",
        "hi": "बिजली विभाग मैसेज भेजकर नंबर पर कॉल करने को नहीं कहता और कनेक्शन नहीं काटता। यह ठगी है।",
        "pa": "ਬਿਜਲੀ ਵਿਭਾਗ ਮੈਸੇਜ ਭੇਜ ਕੇ ਨੰਬਰ ਤੇ ਕਾਲ ਕਰਨ ਲਈ ਨਹੀਂ ਕਹਿੰਦਾ। ਇਹ ਠੱਗੀ ਹੈ।",
    },
    "parcel": {
        "en": "Fake courier or customs messages ask for money to release a parcel. Check with the courier on its official number.",
        "hi": "नकली कूरियर/कस्टम संदेश पार्सल छुड़ाने के नाम पर पैसे मांगते हैं। कूरियर के असली नंबर पर पूछें।",
        "pa": "ਨਕਲੀ ਕੋਰੀਅਰ/ਕਸਟਮ ਸੁਨੇਹੇ ਪਾਰਸਲ ਛੁਡਾਉਣ ਦੇ ਨਾਮ ਤੇ ਪੈਸੇ ਮੰਗਦੇ ਹਨ। ਕੋਰੀਅਰ ਦੇ ਅਸਲੀ ਨੰਬਰ ਤੇ ਪੁੱਛੋ।",
    },
    "job_scam": {
        "en": "Easy 'earn daily from home' jobs that ask you to pay or do paid tasks are a well-known scam.",
        "hi": "घर बैठे रोज़ कमाने वाली आसान नौकरी, जिसमें पैसे लगाने पड़ें, ठगी का जाना-पहचाना तरीका है।",
        "pa": "ਘਰ ਬੈਠੇ ਰੋਜ਼ ਕਮਾਉਣ ਵਾਲੀ ਸੌਖੀ ਨੌਕਰੀ, ਜਿਸ ਵਿੱਚ ਪੈਸੇ ਲਾਉਣੇ ਪੈਣ, ਠੱਗੀ ਦਾ ਜਾਣਿਆ-ਪਛਾਣਿਆ ਤਰੀਕਾ ਹੈ।",
    },
    "investment": {
        "en": "Nobody can guarantee big profits or double your money. These investment offers are scams.",
        "hi": "कोई भी बड़े मुनाफे या पैसा दोगुना होने की गारंटी नहीं दे सकता। ऐसे ऑफर ठगी हैं।",
        "pa": "ਕੋਈ ਵੀ ਵੱਡੇ ਮੁਨਾਫ਼ੇ ਜਾਂ ਪੈਸਾ ਦੁੱਗਣਾ ਹੋਣ ਦੀ ਗਾਰੰਟੀ ਨਹੀਂ ਦੇ ਸਕਦਾ। ਅਜਿਹੇ ਆਫਰ ਠੱਗੀ ਹਨ।",
    },
    "family_impersonation": {
        "en": "Someone is pretending to be your child or relative on a new number and asking for money. Call them on their OLD number first.",
        "hi": "कोई नए नंबर से आपका बेटा/बेटी या रिश्तेदार बनकर पैसे मांग रहा है। पहले उनके पुराने नंबर पर फोन करके पूछें।",
        "pa": "ਕੋਈ ਨਵੇਂ ਨੰਬਰ ਤੋਂ ਤੁਹਾਡਾ ਪੁੱਤ/ਧੀ ਜਾਂ ਰਿਸ਼ਤੇਦਾਰ ਬਣ ਕੇ ਪੈਸੇ ਮੰਗ ਰਿਹਾ ਹੈ। ਪਹਿਲਾਂ ਉਨ੍ਹਾਂ ਦੇ ਪੁਰਾਣੇ ਨੰਬਰ ਤੇ ਫੋਨ ਕਰਕੇ ਪੁੱਛੋ।",
    },
    "wrong_transfer": {
        "en": "If money came into your account by mistake, do NOT send it back yourself. Tell your bank. Scammers use this trick to steal more.",
        "hi": "अगर गलती से पैसे आ गए हैं तो खुद वापस न भेजें। अपने बैंक को बताएं। ठग इसी तरीके से और पैसे चुराते हैं।",
        "pa": "ਜੇ ਗਲਤੀ ਨਾਲ ਪੈਸੇ ਆ ਗਏ ਹਨ ਤਾਂ ਆਪ ਵਾਪਸ ਨਾ ਭੇਜੋ। ਆਪਣੇ ਬੈਂਕ ਨੂੰ ਦੱਸੋ। ਠੱਗ ਇਸੇ ਤਰੀਕੇ ਨਾਲ ਹੋਰ ਪੈਸੇ ਚੋਰੀ ਕਰਦੇ ਹਨ।",
    },
    "credentials": {
        "en": "Someone wants your password or login details. Never share these.",
        "hi": "कोई आपका पासवर्ड या लॉगिन जानकारी मांग रहा है। यह कभी किसी को न दें।",
        "pa": "ਕੋਈ ਤੁਹਾਡਾ ਪਾਸਵਰਡ ਜਾਂ ਲੌਗਿਨ ਜਾਣਕਾਰੀ ਮੰਗ ਰਿਹਾ ਹੈ। ਇਹ ਕਿਸੇ ਨੂੰ ਨਾ ਦਿਓ।",
    },
    "block_threat": {
        "en": "It scares you with 'your account/SIM/card will be blocked' so you act without thinking. Banks do not do this.",
        "hi": "'खाता/सिम/कार्ड बंद हो जाएगा' कहकर डराया जा रहा है ताकि आप बिना सोचे करें। बैंक ऐसा नहीं करते।",
        "pa": "'ਖਾਤਾ/ਸਿਮ/ਕਾਰਡ ਬੰਦ ਹੋ ਜਾਵੇਗਾ' ਕਹਿ ਕੇ ਡਰਾਇਆ ਜਾ ਰਿਹਾ ਹੈ ਤਾਂ ਜੋ ਤੁਸੀਂ ਬਿਨਾਂ ਸੋਚੇ ਕਰੋ। ਬੈਂਕ ਅਜਿਹਾ ਨਹੀਂ ਕਰਦੇ।",
    },
    "link_link": {
        "en": "The link in this message looks fake or dangerous.",
        "hi": "इस मैसेज का लिंक नकली या खतरनाक लग रहा है।",
        "pa": "ਇਸ ਮੈਸੇਜ ਦਾ ਲਿੰਕ ਨਕਲੀ ਜਾਂ ਖ਼ਤਰਨਾਕ ਲੱਗਦਾ ਹੈ।",
    },
    "link_bait": {
        "en": "It pushes you to tap a link. Do not open links from unknown senders.",
        "hi": "यह आपको लिंक दबाने के लिए कह रहा है। अनजान भेजने वाले का लिंक न खोलें।",
        "pa": "ਇਹ ਤੁਹਾਨੂੰ ਲਿੰਕ ਦਬਾਉਣ ਲਈ ਕਹਿ ਰਿਹਾ ਹੈ। ਅਣਜਾਣ ਭੇਜਣ ਵਾਲੇ ਦਾ ਲਿੰਕ ਨਾ ਖੋਲ੍ਹੋ।",
    },
    "urgency": {
        "en": "It rushes you. Scammers create panic so you do not stop to think.",
        "hi": "यह आपको जल्दबाज़ी में डाल रहा है। ठग घबराहट पैदा करते हैं ताकि आप सोच न सकें।",
        "pa": "ਇਹ ਤੁਹਾਨੂੰ ਕਾਹਲੀ ਵਿੱਚ ਪਾ ਰਿਹਾ ਹੈ। ਠੱਗ ਘਬਰਾਹਟ ਪੈਦਾ ਕਰਦੇ ਹਨ ਤਾਂ ਜੋ ਤੁਸੀਂ ਸੋਚ ਨਾ ਸਕੋ।",
    },
    "impersonation": {
        "en": "It uses a bank or government name, but the message itself did not come from an official source.",
        "hi": "इसमें बैंक या सरकारी नाम इस्तेमाल हुआ है, पर मैसेज असली स्रोत से नहीं आया।",
        "pa": "ਇਸ ਵਿੱਚ ਬੈਂਕ ਜਾਂ ਸਰਕਾਰੀ ਨਾਮ ਵਰਤਿਆ ਗਿਆ ਹੈ, ਪਰ ਮੈਸੇਜ ਅਸਲੀ ਸਰੋਤ ਤੋਂ ਨਹੀਂ ਆਇਆ।",
    },
    "safe": {
        "en": "I found nothing that looks like a known scam trick.",
        "hi": "इसमें ठगी के जाने-पहचाने तरीके नहीं दिखे।",
        "pa": "ਇਸ ਵਿੱਚ ਠੱਗੀ ਦੇ ਜਾਣੇ-ਪਛਾਣੇ ਤਰੀਕੇ ਨਹੀਂ ਦਿਖੇ।",
    },
    "protective": {
        "en": "This looks like a normal bank notice that warns you not to share your OTP.",
        "hi": "यह सामान्य बैंक सूचना लगती है जो OTP साझा न करने की चेतावनी देती है।",
        "pa": "ਇਹ ਆਮ ਬੈਂਕ ਸੂਚਨਾ ਲੱਗਦੀ ਹੈ ਜੋ OTP ਸਾਂਝਾ ਨਾ ਕਰਨ ਦੀ ਚੇਤਾਵਨੀ ਦਿੰਦੀ ਹੈ।",
    },
}

# Which category to explain first when several fire.
REASON_PRIORITY = (
    "pin", "upi_collect", "remote_access", "malware", "otp", "legal_threat", "extortion", "kyc",
    "advance_fee", "lottery", "electricity", "parcel", "job_scam", "investment", "family_impersonation", "wrong_transfer", "credentials",
    "block_threat", "link_link", "link_bait", "urgency", "impersonation",
)

ADVICE = {
    "scam": {
        "en": "What to do: ❌ Do not click links. ❌ Never share OTP/PIN. 📞 If money was lost, call 1930 right away. Send *REPORT* to file a complaint.",
        "hi": "क्या करें: ❌ लिंक न खोलें। ❌ OTP/PIN न बताएं। 📞 पैसे कट गए हों तो तुरंत 1930 पर कॉल करें। शिकायत के लिए *REPORT* भेजें।",
        "pa": "ਕੀ ਕਰੀਏ: ❌ ਲਿੰਕ ਨਾ ਖੋਲ੍ਹੋ। ❌ OTP/PIN ਨਾ ਦੱਸੋ। 📞 ਪੈਸੇ ਕੱਟ ਗਏ ਹੋਣ ਤਾਂ ਤੁਰੰਤ 1930 ਤੇ ਕਾਲ ਕਰੋ। ਸ਼ਿਕਾਇਤ ਲਈ *REPORT* ਭੇਜੋ।",
    },
    "suspicious": {
        "en": "What to do: Do not click or reply yet. Call your bank on the number printed on your card or passbook. Ask a family member.",
        "hi": "क्या करें: अभी न क्लिक करें, न जवाब दें। अपने कार्ड/पासबुक पर छपे नंबर पर बैंक को फोन करें। घर के किसी सदस्य से पूछें।",
        "pa": "ਕੀ ਕਰੀਏ: ਹੁਣੇ ਨਾ ਕਲਿੱਕ ਕਰੋ, ਨਾ ਜਵਾਬ ਦਿਓ। ਆਪਣੇ ਕਾਰਡ/ਪਾਸਬੁੱਕ ਤੇ ਛਪੇ ਨੰਬਰ ਤੇ ਬੈਂਕ ਨੂੰ ਫੋਨ ਕਰੋ। ਘਰ ਦੇ ਕਿਸੇ ਮੈਂਬਰ ਤੋਂ ਪੁੱਛੋ।",
    },
    "safe": {"en": "", "hi": "", "pa": ""},
}

WELCOME = {
    "en": (
        "🙏 Namaste! I am *SurakshaSathi*, your free scam guard.\n\n"
        "📩 Forward me any suspicious message, link, screenshot or voice note and I will tell you if it is a scam.\n\n"
        "Commands:\n"
        "• *HINDI* / *PUNJABI* / *ENGLISH* – change language\n"
        "• *FAMILY <number>* – add a family member who gets alerts\n"
        "• *REPORT* – file a cybercrime complaint for the last scam\n"
        "• *TIP* – today's scam lesson\n"
        "• *HELP* – show this again\n\n"
        "If you lose money, call *1930* immediately."
    ),
    "hi": (
        "🙏 नमस्ते! मैं *सुरक्षा साथी* हूँ, आपका मुफ़्त ठगी-रक्षक।\n\n"
        "📩 कोई भी शक वाला मैसेज, लिंक, स्क्रीनशॉट या वॉइस नोट मुझे भेजें। मैं बताऊँगा कि यह ठगी है या नहीं।\n\n"
        "कमांड:\n"
        "• *HINDI* / *PUNJABI* / *ENGLISH* – भाषा बदलें\n"
        "• *FAMILY <नंबर>* – परिवार के सदस्य को जोड़ें जिसे अलर्ट मिलेगा\n"
        "• *REPORT* – पिछली ठगी की साइबर शिकायत तैयार करें\n"
        "• *TIP* – आज की सीख\n"
        "• *HELP* – यह संदेश फिर देखें\n\n"
        "पैसे कट जाएं तो तुरंत *1930* पर कॉल करें।"
    ),
    "pa": (
        "🙏 ਸਤ ਸ੍ਰੀ ਅਕਾਲ! ਮੈਂ *ਸੁਰੱਖਿਆ ਸਾਥੀ* ਹਾਂ, ਤੁਹਾਡਾ ਮੁਫ਼ਤ ਠੱਗੀ-ਰੱਖਿਅਕ।\n\n"
        "📩 ਕੋਈ ਵੀ ਸ਼ੱਕੀ ਮੈਸੇਜ, ਲਿੰਕ, ਸਕ੍ਰੀਨਸ਼ਾਟ ਜਾਂ ਵੌਇਸ ਨੋਟ ਮੈਨੂੰ ਭੇਜੋ। ਮੈਂ ਦੱਸਾਂਗਾ ਕਿ ਇਹ ਠੱਗੀ ਹੈ ਜਾਂ ਨਹੀਂ।\n\n"
        "ਕਮਾਂਡ:\n"
        "• *HINDI* / *PUNJABI* / *ENGLISH* – ਭਾਸ਼ਾ ਬਦਲੋ\n"
        "• *FAMILY <ਨੰਬਰ>* – ਪਰਿਵਾਰ ਦਾ ਮੈਂਬਰ ਜੋੜੋ ਜਿਸਨੂੰ ਅਲਰਟ ਮਿਲੇਗਾ\n"
        "• *REPORT* – ਪਿਛਲੀ ਠੱਗੀ ਦੀ ਸਾਈਬਰ ਸ਼ਿਕਾਇਤ ਤਿਆਰ ਕਰੋ\n"
        "• *TIP* – ਅੱਜ ਦੀ ਸਿੱਖਿਆ\n"
        "• *HELP* – ਇਹ ਸੁਨੇਹਾ ਦੁਬਾਰਾ ਵੇਖੋ\n\n"
        "ਪੈਸੇ ਕੱਟ ਜਾਣ ਤਾਂ ਤੁਰੰਤ *1930* ਤੇ ਕਾਲ ਕਰੋ।"
    ),
}

T = {
    "lang_set": {
        "en": "✅ Language set to English.",
        "hi": "✅ भाषा हिन्दी कर दी गई है।",
        "pa": "✅ ਭਾਸ਼ਾ ਪੰਜਾਬੀ ਕਰ ਦਿੱਤੀ ਗਈ ਹੈ।",
    },
    "send_something": {
        "en": "Please forward the suspicious message, link, screenshot or voice note to me. Send *HELP* to see what I can do.",
        "hi": "कृपया शक वाला मैसेज, लिंक, स्क्रीनशॉट या वॉइस नोट मुझे भेजें। मैं क्या कर सकता हूँ, यह देखने के लिए *HELP* भेजें।",
        "pa": "ਕਿਰਪਾ ਕਰਕੇ ਸ਼ੱਕੀ ਮੈਸੇਜ, ਲਿੰਕ, ਸਕ੍ਰੀਨਸ਼ਾਟ ਜਾਂ ਵੌਇਸ ਨੋਟ ਮੈਨੂੰ ਭੇਜੋ। ਮੈਂ ਕੀ ਕਰ ਸਕਦਾ ਹਾਂ, ਵੇਖਣ ਲਈ *HELP* ਭੇਜੋ।",
    },
    "family_added": {
        "en": "✅ Added {number} as your family guardian. They will get an alert if you receive a serious scam.",
        "hi": "✅ {number} को आपका परिवार रक्षक जोड़ दिया गया। गंभीर ठगी आने पर उन्हें अलर्ट मिलेगा।",
        "pa": "✅ {number} ਨੂੰ ਤੁਹਾਡਾ ਪਰਿਵਾਰਕ ਰੱਖਿਅਕ ਜੋੜ ਦਿੱਤਾ ਗਿਆ। ਗੰਭੀਰ ਠੱਗੀ ਆਉਣ ਤੇ ਉਨ੍ਹਾਂ ਨੂੰ ਅਲਰਟ ਮਿਲੇਗਾ।",
    },
    "family_bad": {
        "en": "That number does not look right. Send like: *FAMILY 9876543210*",
        "hi": "यह नंबर सही नहीं लग रहा। ऐसे भेजें: *FAMILY 9876543210*",
        "pa": "ਇਹ ਨੰਬਰ ਸਹੀ ਨਹੀਂ ਲੱਗਦਾ। ਇਸ ਤਰ੍ਹਾਂ ਭੇਜੋ: *FAMILY 9876543210*",
    },
    "family_alerted": {
        "en": "👨‍👩‍👧 I have also warned your family guardian.",
        "hi": "👨‍👩‍👧 मैंने आपके परिवार रक्षक को भी सूचित कर दिया है।",
        "pa": "👨‍👩‍👧 ਮੈਂ ਤੁਹਾਡੇ ਪਰਿਵਾਰਕ ਰੱਖਿਅਕ ਨੂੰ ਵੀ ਸੂਚਿਤ ਕਰ ਦਿੱਤਾ ਹੈ।",
    },
    "family_hint": {
        "en": "Tip: send *FAMILY <number>* so a family member is warned when you get a serious scam.",
        "hi": "सुझाव: *FAMILY <नंबर>* भेजें ताकि गंभीर ठगी आने पर परिवार के सदस्य को खबर मिले।",
        "pa": "ਸੁਝਾਅ: *FAMILY <ਨੰਬਰ>* ਭੇਜੋ ਤਾਂ ਜੋ ਗੰਭੀਰ ਠੱਗੀ ਆਉਣ ਤੇ ਪਰਿਵਾਰ ਦੇ ਮੈਂਬਰ ਨੂੰ ਖ਼ਬਰ ਮਿਲੇ।",
    },
    "no_report": {
        "en": "I have no scam on record from you yet. Forward a suspicious message first, then send *REPORT*.",
        "hi": "आपकी कोई ठगी अभी दर्ज नहीं है। पहले शक वाला मैसेज भेजें, फिर *REPORT* भेजें।",
        "pa": "ਤੁਹਾਡੀ ਕੋਈ ਠੱਗੀ ਅਜੇ ਦਰਜ ਨਹੀਂ ਹੈ। ਪਹਿਲਾਂ ਸ਼ੱਕੀ ਮੈਸੇਜ ਭੇਜੋ, ਫਿਰ *REPORT* ਭੇਜੋ।",
    },
    "report_intro": {
        "en": "📝 Your complaint is ready. Open https://cybercrime.gov.in or call *1930*, and use the text below. If money was lost, call 1930 FIRST (the first hour matters most).",
        "hi": "📝 आपकी शिकायत तैयार है। https://cybercrime.gov.in खोलें या *1930* पर कॉल करें और नीचे का पाठ इस्तेमाल करें। पैसे कटे हों तो पहले 1930 पर कॉल करें (पहला घंटा सबसे ज़रूरी है)।",
        "pa": "📝 ਤੁਹਾਡੀ ਸ਼ਿਕਾਇਤ ਤਿਆਰ ਹੈ। https://cybercrime.gov.in ਖੋਲ੍ਹੋ ਜਾਂ *1930* ਤੇ ਕਾਲ ਕਰੋ ਅਤੇ ਹੇਠਾਂ ਦਾ ਪਾਠ ਵਰਤੋ। ਪੈਸੇ ਕੱਟੇ ਹੋਣ ਤਾਂ ਪਹਿਲਾਂ 1930 ਤੇ ਕਾਲ ਕਰੋ (ਪਹਿਲਾ ਘੰਟਾ ਸਭ ਤੋਂ ਜ਼ਰੂਰੀ ਹੈ)।",
    },
    "district_ask": {
        "en": "📍 To show scam hotspots on our map, reply with your *district* (example: DISTRICT Ambala). This is optional.",
        "hi": "📍 नक्शे पर ठगी वाले इलाके दिखाने के लिए अपना *ज़िला* भेजें (उदाहरण: DISTRICT Ambala)। यह वैकल्पिक है।",
        "pa": "📍 ਨਕਸ਼ੇ ਤੇ ਠੱਗੀ ਵਾਲੇ ਇਲਾਕੇ ਵਿਖਾਉਣ ਲਈ ਆਪਣਾ *ਜ਼ਿਲ੍ਹਾ* ਭੇਜੋ (ਉਦਾਹਰਣ: DISTRICT Ambala)। ਇਹ ਜ਼ਰੂਰੀ ਨਹੀਂ।",
    },
    "district_set": {
        "en": "✅ District saved: {district}. Thank you for helping protect your area.",
        "hi": "✅ ज़िला सेव हो गया: {district}। अपने इलाके को सुरक्षित रखने में मदद के लिए धन्यवाद।",
        "pa": "✅ ਜ਼ਿਲ੍ਹਾ ਸੇਵ ਹੋ ਗਿਆ: {district}। ਆਪਣੇ ਇਲਾਕੇ ਨੂੰ ਸੁਰੱਖਿਅਤ ਰੱਖਣ ਵਿੱਚ ਮਦਦ ਲਈ ਧੰਨਵਾਦ।",
    },
    "district_unknown": {
        "en": "I do not know that district yet. Try the district's English name, like *DISTRICT Ludhiana*.",
        "hi": "यह ज़िला मुझे अभी नहीं पता। अंग्रेज़ी नाम लिखकर देखें, जैसे *DISTRICT Ludhiana*।",
        "pa": "ਇਹ ਜ਼ਿਲ੍ਹਾ ਮੈਨੂੰ ਅਜੇ ਨਹੀਂ ਪਤਾ। ਅੰਗਰੇਜ਼ੀ ਨਾਮ ਲਿਖ ਕੇ ਵੇਖੋ, ਜਿਵੇਂ *DISTRICT Ludhiana*।",
    },
    "voice_failed": {
        "en": "I could not understand the voice note. Please type or forward the message as text, or try recording again.",
        "hi": "मैं वॉइस नोट समझ नहीं पाया। कृपया मैसेज टाइप करके भेजें या दोबारा रिकॉर्ड करें।",
        "pa": "ਮੈਂ ਵੌਇਸ ਨੋਟ ਸਮਝ ਨਹੀਂ ਸਕਿਆ। ਕਿਰਪਾ ਕਰਕੇ ਮੈਸੇਜ ਟਾਈਪ ਕਰਕੇ ਭੇਜੋ ਜਾਂ ਦੁਬਾਰਾ ਰਿਕਾਰਡ ਕਰੋ।",
    },
    "image_failed": {
        "en": "I could not read the text in that picture. Please send a clearer screenshot or type the message.",
        "hi": "मैं उस फोटो में लिखा पढ़ नहीं पाया। कृपया साफ़ स्क्रीनशॉट भेजें या मैसेज टाइप करें।",
        "pa": "ਮੈਂ ਉਸ ਫੋਟੋ ਵਿੱਚ ਲਿਖਿਆ ਪੜ੍ਹ ਨਹੀਂ ਸਕਿਆ। ਕਿਰਪਾ ਕਰਕੇ ਸਾਫ਼ ਸਕ੍ਰੀਨਸ਼ਾਟ ਭੇਜੋ ਜਾਂ ਮੈਸੇਜ ਟਾਈਪ ਕਰੋ।",
    },
    "heard": {
        "en": "🎙️ I heard: \"{text}\"",
        "hi": "🎙️ मैंने सुना: \"{text}\"",
        "pa": "🎙️ ਮੈਂ ਸੁਣਿਆ: \"{text}\"",
    },
    "link_note": {
        "en": "🔗 Link checked: {host} looks {state}.",
        "hi": "🔗 लिंक जांचा: {host} {state} लग रहा है।",
        "pa": "🔗 ਲਿੰਕ ਜਾਂਚਿਆ: {host} {state} ਲੱਗਦਾ ਹੈ।",
    },
    "link_state_bad": {"en": "dangerous", "hi": "खतरनाक", "pa": "ਖ਼ਤਰਨਾਕ"},
    "link_state_warn": {"en": "suspicious", "hi": "संदिग्ध", "pa": "ਸ਼ੱਕੀ"},
    "lesson_title": {
        "en": "📚 Scam of the Day",
        "hi": "📚 आज की ठगी से सीख",
        "pa": "📚 ਅੱਜ ਦੀ ਠੱਗੀ ਤੋਂ ਸਿੱਖਿਆ",
    },
}


def tr(key: str, lang: str, **fmt: str) -> str:
    table = T[key]
    text = table.get(lang) or table["en"]
    return text.format(**fmt) if fmt else text


def reason_for(categories: list[str], lang: str, link_flagged: bool = False) -> str:
    cats = set(categories)
    if link_flagged:
        cats.add("link_link")
    for key in REASON_PRIORITY:
        if key in cats:
            return REASONS[key].get(lang) or REASONS[key]["en"]
    return REASONS["safe"].get(lang) or REASONS["safe"]["en"]
