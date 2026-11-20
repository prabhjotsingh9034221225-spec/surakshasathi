"""Stall-reply assistant: a safe message the *person* can send to waste a scammer's time without revealing anything.

Human in the loop by design: SurakshaSathi never contacts the scammer, never sends from the user's number, never
shares personal data. The reply is text for the user to copy, send once, then block and report.
"""
from __future__ import annotations

_R = {
    "legal_threat": {
        "en": "I will not discuss this on a phone or video call. Please send the official notice and FIR number in writing to my address. I am going to the nearest police station in person with my family and will verify it there.",
        "hi": "मैं इस बारे में फोन या वीडियो कॉल पर बात नहीं करूँगा। कृपया आधिकारिक नोटिस और FIR नंबर लिखित में मेरे पते पर भेजें। मैं अपने परिवार के साथ नज़दीकी थाने जाकर खुद जाँच करूँगा।",
        "pa": "ਮੈਂ ਇਸ ਬਾਰੇ ਫ਼ੋਨ ਜਾਂ ਵੀਡੀਓ ਕਾਲ ਤੇ ਗੱਲ ਨਹੀਂ ਕਰਾਂਗਾ। ਕਿਰਪਾ ਕਰਕੇ ਸਰਕਾਰੀ ਨੋਟਿਸ ਅਤੇ FIR ਨੰਬਰ ਲਿਖਤੀ ਰੂਪ ਵਿੱਚ ਮੇਰੇ ਪਤੇ ਤੇ ਭੇਜੋ। ਮੈਂ ਪਰਿਵਾਰ ਨਾਲ ਨੇੜਲੇ ਥਾਣੇ ਜਾ ਕੇ ਆਪ ਜਾਂਚ ਕਰਾਂਗਾ।",
    },
    "family_impersonation": {
        "en": "I will call you back on your old number first. Before that, tell me something only you would know, like what you called me as a child.",
        "hi": "मैं पहले आपके पुराने नंबर पर कॉल करूँगा। उससे पहले कोई ऐसी बात बताइए जो सिर्फ आप जानते हों, जैसे बचपन में आप मुझे क्या कहकर बुलाते थे।",
        "pa": "ਮੈਂ ਪਹਿਲਾਂ ਤੁਹਾਡੇ ਪੁਰਾਣੇ ਨੰਬਰ ਤੇ ਕਾਲ ਕਰਾਂਗਾ। ਉਸ ਤੋਂ ਪਹਿਲਾਂ ਕੋਈ ਅਜਿਹੀ ਗੱਲ ਦੱਸੋ ਜੋ ਸਿਰਫ਼ ਤੁਸੀਂ ਜਾਣਦੇ ਹੋ, ਜਿਵੇਂ ਬਚਪਨ ਵਿੱਚ ਮੈਨੂੰ ਕੀ ਕਹਿ ਕੇ ਬੁਲਾਉਂਦੇ ਸੀ।",
    },
    "lottery": {
        "en": "Thank you. Please deduct any fee or tax from the prize amount and send the rest to my bank, since I do not pay anything in advance. Also send your company registration number and a written letter.",
        "hi": "धन्यवाद। कृपया कोई भी फीस या टैक्स इनाम की रकम से काट लें और बाकी मेरे बैंक में भेज दें, मैं पहले कोई पैसा नहीं देता। साथ में अपनी कंपनी का रजिस्ट्रेशन नंबर और लिखित पत्र भी भेजें।",
        "pa": "ਧੰਨਵਾਦ। ਕਿਰਪਾ ਕਰਕੇ ਕੋਈ ਵੀ ਫੀਸ ਜਾਂ ਟੈਕਸ ਇਨਾਮ ਦੀ ਰਕਮ ਵਿੱਚੋਂ ਕੱਟ ਲਓ ਅਤੇ ਬਾਕੀ ਮੇਰੇ ਬੈਂਕ ਵਿੱਚ ਭੇਜੋ, ਮੈਂ ਪਹਿਲਾਂ ਕੋਈ ਪੈਸਾ ਨਹੀਂ ਦਿੰਦਾ। ਨਾਲ ਆਪਣੀ ਕੰਪਨੀ ਦਾ ਰਜਿਸਟ੍ਰੇਸ਼ਨ ਨੰਬਰ ਅਤੇ ਲਿਖਤੀ ਚਿੱਠੀ ਵੀ ਭੇਜੋ।",
    },
    "job_scam": {
        "en": "Please send your company registration (CIN), GST number and an official offer letter on company email. I will verify them with the government portal before I do anything.",
        "hi": "कृपया कंपनी का रजिस्ट्रेशन (CIN), GST नंबर और कंपनी ईमेल से आधिकारिक ऑफर लेटर भेजें। कुछ भी करने से पहले मैं सरकारी पोर्टल पर इन्हें जाँचूँगा।",
        "pa": "ਕਿਰਪਾ ਕਰਕੇ ਕੰਪਨੀ ਦਾ ਰਜਿਸਟ੍ਰੇਸ਼ਨ (CIN), GST ਨੰਬਰ ਅਤੇ ਕੰਪਨੀ ਈਮੇਲ ਤੋਂ ਅਧਿਕਾਰਤ ਆਫ਼ਰ ਲੈਟਰ ਭੇਜੋ। ਕੁਝ ਵੀ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਮੈਂ ਸਰਕਾਰੀ ਪੋਰਟਲ ਤੇ ਇਨ੍ਹਾਂ ਦੀ ਜਾਂਚ ਕਰਾਂਗਾ।",
    },
    "default": {
        "en": "I am not at my phone and my son or daughter handles all my banking. Please send your full name, employee ID and the office landline number in writing. I will call the official number printed on my bank card and get back to you.",
        "hi": "मैं अभी फोन के पास नहीं हूँ और मेरा बैंक का सारा काम मेरे बेटे या बेटी देखते हैं। कृपया अपना पूरा नाम, कर्मचारी आईडी और दफ़्तर का लैंडलाइन नंबर लिखकर भेजें। मैं अपने बैंक कार्ड पर छपे आधिकारिक नंबर पर कॉल करके आपको बताऊँगा।",
        "pa": "ਮੈਂ ਹੁਣ ਫ਼ੋਨ ਕੋਲ ਨਹੀਂ ਹਾਂ ਅਤੇ ਮੇਰਾ ਬੈਂਕ ਦਾ ਸਾਰਾ ਕੰਮ ਮੇਰਾ ਪੁੱਤਰ ਜਾਂ ਧੀ ਵੇਖਦੇ ਹਨ। ਕਿਰਪਾ ਕਰਕੇ ਆਪਣਾ ਪੂਰਾ ਨਾਮ, ਕਰਮਚਾਰੀ ਆਈਡੀ ਅਤੇ ਦਫ਼ਤਰ ਦਾ ਲੈਂਡਲਾਈਨ ਨੰਬਰ ਲਿਖ ਕੇ ਭੇਜੋ। ਮੈਂ ਆਪਣੇ ਬੈਂਕ ਕਾਰਡ ਤੇ ਛਪੇ ਅਧਿਕਾਰਤ ਨੰਬਰ ਤੇ ਕਾਲ ਕਰਕੇ ਤੁਹਾਨੂੰ ਦੱਸਾਂਗਾ।",
    },
}
_ALIAS = {"investment": "job_scam", "advance_fee": "lottery", "parcel": "legal_threat", "extortion": "legal_threat"}
_RULES = {
    "en": ["Send this once from your own chat, then stop replying. Do not argue.", "Never share an OTP, PIN, card number or any personal detail, even to 'prove' something.", "Do not click their links or call their numbers.", "Then block the number and report it: 1930 or cybercrime.gov.in."],
    "hi": ["इसे अपनी चैट से एक बार भेजें, फिर जवाब देना बंद करें। बहस न करें।", "कुछ 'साबित' करने के लिए भी OTP, PIN, कार्ड नंबर या कोई निजी जानकारी न दें।", "उनके लिंक न खोलें और उनके नंबर पर कॉल न करें।", "फिर नंबर ब्लॉक करें और शिकायत करें: 1930 या cybercrime.gov.in।"],
    "pa": ["ਇਹ ਆਪਣੀ ਚੈਟ ਤੋਂ ਇੱਕ ਵਾਰ ਭੇਜੋ, ਫਿਰ ਜਵਾਬ ਦੇਣਾ ਬੰਦ ਕਰੋ। ਬਹਿਸ ਨਾ ਕਰੋ।", "ਕੁਝ 'ਸਾਬਤ' ਕਰਨ ਲਈ ਵੀ OTP, PIN, ਕਾਰਡ ਨੰਬਰ ਜਾਂ ਕੋਈ ਨਿੱਜੀ ਜਾਣਕਾਰੀ ਨਾ ਦਿਓ।", "ਉਨ੍ਹਾਂ ਦੇ ਲਿੰਕ ਨਾ ਖੋਲ੍ਹੋ ਅਤੇ ਉਨ੍ਹਾਂ ਦੇ ਨੰਬਰ ਤੇ ਕਾਲ ਨਾ ਕਰੋ।", "ਫਿਰ ਨੰਬਰ ਬਲੌਕ ਕਰੋ ਅਤੇ ਸ਼ਿਕਾਇਤ ਕਰੋ: 1930 ਜਾਂ cybercrime.gov.in।"],
}


def suggest(categories: list[str], lang: str = "en") -> dict:
    lang = lang if lang in ("en", "hi", "pa") else "en"
    key = next((_ALIAS.get(c, c) for c in categories if _ALIAS.get(c, c) in _R), "default")
    return {"category": key, "reply": _R[key][lang], "rules": _RULES[lang]}
