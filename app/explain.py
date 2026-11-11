"""Plain-language explanation, next steps and reporting guidance for an Analysis."""
from __future__ import annotations

# Why each warning sign matters, in simple words (en / hi / pa).
WHY = {
    "otp": {
        "en": "It asks for an OTP. Real banks and apps never ask you to share an OTP.",
        "hi": "इसमें OTP मांगा गया है। असली बैंक या ऐप कभी OTP नहीं मांगते।",
        "pa": "ਇਸ ਵਿੱਚ OTP ਮੰਗਿਆ ਗਿਆ ਹੈ। ਅਸਲੀ ਬੈਂਕ ਜਾਂ ਐਪ ਕਦੇ OTP ਨਹੀਂ ਮੰਗਦੇ।",
    },
    "pin": {
        "en": "It asks for your UPI or ATM PIN. You never need a PIN to receive money.",
        "hi": "इसमें UPI या ATM PIN मांगा गया है। पैसे पाने के लिए PIN की ज़रूरत कभी नहीं होती।",
        "pa": "ਇਸ ਵਿੱਚ UPI ਜਾਂ ATM PIN ਮੰਗਿਆ ਗਿਆ ਹੈ। ਪੈਸੇ ਲੈਣ ਲਈ PIN ਦੀ ਲੋੜ ਨਹੀਂ ਹੁੰਦੀ।",
    },
    "credentials": {
        "en": "It asks for a password or login details.",
        "hi": "इसमें पासवर्ड या लॉगिन जानकारी मांगी गई है।",
        "pa": "ਇਸ ਵਿੱਚ ਪਾਸਵਰਡ ਜਾਂ ਲੌਗਇਨ ਜਾਣਕਾਰੀ ਮੰਗੀ ਗਈ ਹੈ।",
    },
    "kyc": {
        "en": "It says your KYC must be updated through a message or link. Banks do not do this.",
        "hi": "इसमें कहा गया है कि KYC मैसेज या लिंक से अपडेट करें। बैंक ऐसा नहीं करते।",
        "pa": "ਇਸ ਵਿੱਚ ਕਿਹਾ ਗਿਆ ਹੈ ਕਿ KYC ਮੈਸੇਜ ਜਾਂ ਲਿੰਕ ਰਾਹੀਂ ਅੱਪਡੇਟ ਕਰੋ। ਬੈਂਕ ਇਹ ਨਹੀਂ ਕਰਦੇ।",
    },
    "block_threat": {
        "en": "It threatens that your account will be blocked. Scammers use fear to rush you.",
        "hi": "इसमें अकाउंट बंद होने की धमकी है। ठग डर दिखाकर जल्दी करवाते हैं।",
        "pa": "ਇਸ ਵਿੱਚ ਖਾਤਾ ਬੰਦ ਹੋਣ ਦੀ ਧਮਕੀ ਹੈ। ਠੱਗ ਡਰਾ ਕੇ ਜਲਦੀ ਕਰਵਾਉਂਦੇ ਹਨ।",
    },
    "urgency": {
        "en": "It pushes you to act immediately. Real organisations give you time.",
        "hi": "यह आपको तुरंत कदम उठाने के लिए दबाव डालता है। असली संस्थाएं समय देती हैं।",
        "pa": "ਇਹ ਤੁਹਾਨੂੰ ਤੁਰੰਤ ਕਦਮ ਚੁੱਕਣ ਲਈ ਮਜਬੂਰ ਕਰਦਾ ਹੈ। ਅਸਲੀ ਸੰਸਥਾਵਾਂ ਸਮਾਂ ਦਿੰਦੀਆਂ ਹਨ।",
    },
    "legal_threat": {
        "en": "It threatens arrest, police or court action. Police never ask for money on a call or message.",
        "hi": "इसमें गिरफ्तारी, पुलिस या कोर्ट की धमकी है। पुलिस कभी फोन या मैसेज पर पैसे नहीं मांगती।",
        "pa": "ਇਸ ਵਿੱਚ ਗ੍ਰਿਫ਼ਤਾਰੀ, ਪੁਲਿਸ ਜਾਂ ਅਦਾਲਤ ਦੀ ਧਮਕੀ ਹੈ। ਪੁਲਿਸ ਕਦੇ ਫ਼ੋਨ ਜਾਂ ਮੈਸੇਜ ਤੇ ਪੈਸੇ ਨਹੀਂ ਮੰਗਦੀ।",
    },
    "lottery": {
        "en": "It promises a prize or lottery you never entered.",
        "hi": "इसमें ऐसे इनाम या लॉटरी का वादा है जिसमें आपने हिस्सा ही नहीं लिया।",
        "pa": "ਇਸ ਵਿੱਚ ਅਜਿਹੇ ਇਨਾਮ ਜਾਂ ਲਾਟਰੀ ਦਾ ਵਾਅਦਾ ਹੈ ਜਿਸ ਵਿੱਚ ਤੁਸੀਂ ਹਿੱਸਾ ਹੀ ਨਹੀਂ ਲਿਆ।",
    },
    "advance_fee": {
        "en": "It asks you to pay a small fee first to receive something bigger.",
        "hi": "इसमें बड़ा फायदा पाने के लिए पहले छोटी फीस मांगी गई है।",
        "pa": "ਇਸ ਵਿੱਚ ਵੱਡਾ ਫਾਇਦਾ ਲੈਣ ਲਈ ਪਹਿਲਾਂ ਛੋਟੀ ਫੀਸ ਮੰਗੀ ਗਈ ਹੈ।",
    },
    "job_scam": {
        "en": "It offers easy money for simple tasks. This is a common job scam.",
        "hi": "यह आसान कामों के बदले आसान कमाई का लालच देता है। यह नौकरी की आम ठगी है।",
        "pa": "ਇਹ ਸੌਖੇ ਕੰਮਾਂ ਬਦਲੇ ਸੌਖੀ ਕਮਾਈ ਦਾ ਲਾਲਚ ਦਿੰਦਾ ਹੈ। ਇਹ ਨੌਕਰੀ ਦੀ ਆਮ ਠੱਗੀ ਹੈ।",
    },
    "investment": {
        "en": "It promises very high or guaranteed returns. No real investment does this.",
        "hi": "इसमें बहुत ज़्यादा या पक्के मुनाफे का वादा है। कोई असली निवेश ऐसा नहीं करता।",
        "pa": "ਇਸ ਵਿੱਚ ਬਹੁਤ ਜ਼ਿਆਦਾ ਜਾਂ ਪੱਕੇ ਮੁਨਾਫ਼ੇ ਦਾ ਵਾਅਦਾ ਹੈ। ਕੋਈ ਅਸਲੀ ਨਿਵੇਸ਼ ਅਜਿਹਾ ਨਹੀਂ ਕਰਦਾ।",
    },
    "upi_collect": {
        "en": "It asks you to approve a UPI request to receive money. Approving sends money out.",
        "hi": "इसमें पैसे पाने के नाम पर UPI रिक्वेस्ट मंज़ूर करने को कहा गया है। मंज़ूर करने से पैसे कट जाते हैं।",
        "pa": "ਇਸ ਵਿੱਚ ਪੈਸੇ ਲੈਣ ਦੇ ਨਾਂ ਤੇ UPI ਬੇਨਤੀ ਮਨਜ਼ੂਰ ਕਰਨ ਨੂੰ ਕਿਹਾ ਗਿਆ ਹੈ। ਮਨਜ਼ੂਰ ਕਰਨ ਨਾਲ ਪੈਸੇ ਕੱਟ ਜਾਂਦੇ ਹਨ।",
    },
    "wrong_transfer": {
        "en": "It claims money was sent to you by mistake and asks you to return it.",
        "hi": "इसमें कहा गया है कि गलती से आपको पैसे भेजे गए हैं और लौटाने को कहा गया है।",
        "pa": "ਇਸ ਵਿੱਚ ਕਿਹਾ ਗਿਆ ਹੈ ਕਿ ਗਲਤੀ ਨਾਲ ਤੁਹਾਨੂੰ ਪੈਸੇ ਭੇਜੇ ਗਏ ਹਨ ਅਤੇ ਮੋੜਨ ਨੂੰ ਕਿਹਾ ਗਿਆ ਹੈ।",
    },
    "family_impersonation": {
        "en": "Someone claims to be a relative with a new number and asks for money. Call them on their old number first.",
        "hi": "कोई नए नंबर से रिश्तेदार बनकर पैसे मांग रहा है। पहले उनके पुराने नंबर पर फोन करें।",
        "pa": "ਕੋਈ ਨਵੇਂ ਨੰਬਰ ਤੋਂ ਰਿਸ਼ਤੇਦਾਰ ਬਣ ਕੇ ਪੈਸੇ ਮੰਗ ਰਿਹਾ ਹੈ। ਪਹਿਲਾਂ ਉਨ੍ਹਾਂ ਦੇ ਪੁਰਾਣੇ ਨੰਬਰ ਤੇ ਫ਼ੋਨ ਕਰੋ।",
    },
    "remote_access": {
        "en": "It asks you to install a screen-sharing app such as AnyDesk. This lets a stranger see and control your phone.",
        "hi": "इसमें AnyDesk जैसा स्क्रीन-शेयर ऐप डाउनलोड करने को कहा गया है। इससे अजनबी आपका फोन देख और चला सकता है।",
        "pa": "ਇਸ ਵਿੱਚ AnyDesk ਵਰਗੀ ਸਕਰੀਨ-ਸ਼ੇਅਰ ਐਪ ਇੰਸਟਾਲ ਕਰਨ ਨੂੰ ਕਿਹਾ ਗਿਆ ਹੈ। ਇਸ ਨਾਲ ਅਜਨਬੀ ਤੁਹਾਡਾ ਫ਼ੋਨ ਦੇਖ ਤੇ ਚਲਾ ਸਕਦਾ ਹੈ।",
    },
    "malware": {
        "en": "It asks you to install an APK file from outside the Play Store. These often steal data.",
        "hi": "इसमें Play Store के बाहर से APK फाइल डालने को कहा गया है। ऐसी फाइलें अक्सर डेटा चुराती हैं।",
        "pa": "ਇਸ ਵਿੱਚ Play Store ਤੋਂ ਬਾਹਰੋਂ APK ਫਾਈਲ ਇੰਸਟਾਲ ਕਰਨ ਨੂੰ ਕਿਹਾ ਗਿਆ ਹੈ। ਅਜਿਹੀਆਂ ਫਾਈਲਾਂ ਅਕਸਰ ਡੇਟਾ ਚੋਰੀ ਕਰਦੀਆਂ ਹਨ।",
    },
    "impersonation": {
        "en": "It pretends to be a bank or a government office.",
        "hi": "यह खुद को बैंक या सरकारी दफ्तर बता रहा है।",
        "pa": "ਇਹ ਆਪਣੇ ਆਪ ਨੂੰ ਬੈਂਕ ਜਾਂ ਸਰਕਾਰੀ ਦਫ਼ਤਰ ਦੱਸ ਰਿਹਾ ਹੈ।",
    },
    "parcel": {
        "en": "It talks about a parcel or customs charge you did not expect.",
        "hi": "इसमें ऐसे पार्सल या कस्टम चार्ज की बात है जिसकी आपको उम्मीद नहीं थी।",
        "pa": "ਇਸ ਵਿੱਚ ਅਜਿਹੇ ਪਾਰਸਲ ਜਾਂ ਕਸਟਮ ਚਾਰਜ ਦੀ ਗੱਲ ਹੈ ਜਿਸਦੀ ਤੁਹਾਨੂੰ ਉਮੀਦ ਨਹੀਂ ਸੀ।",
    },
    "electricity": {
        "en": "It threatens to cut your electricity tonight unless you pay or call a number.",
        "hi": "इसमें आज रात बिजली कटने की धमकी है जब तक आप पैसे न दें या नंबर पर कॉल न करें।",
        "pa": "ਇਸ ਵਿੱਚ ਅੱਜ ਰਾਤ ਬਿਜਲੀ ਕੱਟਣ ਦੀ ਧਮਕੀ ਹੈ ਜਦੋਂ ਤੱਕ ਤੁਸੀਂ ਪੈਸੇ ਨਾ ਦਿਓ ਜਾਂ ਨੰਬਰ ਤੇ ਕਾਲ ਨਾ ਕਰੋ।",
    },
    "extortion": {
        "en": "It threatens to share private photos or videos. Do not pay. This is blackmail.",
        "hi": "इसमें निजी फोटो या वीडियो फैलाने की धमकी है। पैसे न दें। यह ब्लैकमेल है।",
        "pa": "ਇਸ ਵਿੱਚ ਨਿੱਜੀ ਫੋਟੋ ਜਾਂ ਵੀਡੀਓ ਫੈਲਾਉਣ ਦੀ ਧਮਕੀ ਹੈ। ਪੈਸੇ ਨਾ ਦਿਓ। ਇਹ ਬਲੈਕਮੇਲ ਹੈ।",
    },
    "link_link": {
        "en": "It contains a link that looks unsafe or fake.",
        "hi": "इसमें ऐसा लिंक है जो असुरक्षित या नकली लगता है।",
        "pa": "ਇਸ ਵਿੱਚ ਅਜਿਹਾ ਲਿੰਕ ਹੈ ਜੋ ਅਸੁਰੱਖਿਅਤ ਜਾਂ ਨਕਲੀ ਲੱਗਦਾ ਹੈ।",
    },
    "link_bait": {
        "en": "It nudges you to tap a link.",
        "hi": "यह आपको लिंक दबाने के लिए उकसाता है।",
        "pa": "ਇਹ ਤੁਹਾਨੂੰ ਲਿੰਕ ਦਬਾਉਣ ਲਈ ਉਕਸਾਉਂਦਾ ਹੈ।",
    },
}

LINK_REASONS = {
    "ip_address_host": ("Uses a number address instead of a real website name", "असली वेबसाइट नाम की जगह नंबर वाला पता है", "ਅਸਲੀ ਵੈੱਬਸਾਈਟ ਨਾਂ ਦੀ ਥਾਂ ਨੰਬਰ ਵਾਲਾ ਪਤਾ ਹੈ"),
    "url_shortener": ("Shortened link hides where it really goes", "छोटा लिंक असली जगह छिपाता है", "ਛੋਟਾ ਲਿੰਕ ਅਸਲੀ ਥਾਂ ਲੁਕਾਉਂਦਾ ਹੈ"),
    "punycode_lookalike": ("Look-alike characters imitate a real site", "असली साइट जैसे दिखने वाले नकली अक्षर हैं", "ਅਸਲੀ ਸਾਈਟ ਵਰਗੇ ਦਿੱਸਦੇ ਨਕਲੀ ਅੱਖਰ ਹਨ"),
    "userinfo_trick": ("Trick address that hides the real website", "ऐसा चालाक पता जो असली वेबसाइट छिपाता है", "ਅਜਿਹਾ ਚਾਲਾਕ ਪਤਾ ਜੋ ਅਸਲੀ ਵੈੱਬਸਾਈਟ ਲੁਕਾਉਂਦਾ ਹੈ"),
    "risky_tld": ("Ends in an address type often used by scammers", "ऐसे अंत वाला पता जो ठग अक्सर इस्तेमाल करते हैं", "ਅਜਿਹੇ ਅੰਤ ਵਾਲਾ ਪਤਾ ਜੋ ਠੱਗ ਅਕਸਰ ਵਰਤਦੇ ਹਨ"),
    "apk_download": ("Downloads an APK app file", "APK ऐप फाइल डाउनलोड करवाता है", "APK ਐਪ ਫਾਈਲ ਡਾਊਨਲੋਡ ਕਰਵਾਉਂਦਾ ਹੈ"),
    "many_subdomains": ("Unusually long address with many parts", "बहुत हिस्सों वाला असामान्य लंबा पता", "ਬਹੁਤ ਹਿੱਸਿਆਂ ਵਾਲਾ ਅਸਾਧਾਰਨ ਲੰਮਾ ਪਤਾ"),
    "many_hyphens": ("Address has many hyphens, common in fake sites", "पते में कई हाइफ़न हैं, नकली साइटों में आम", "ਪਤੇ ਵਿੱਚ ਕਈ ਹਾਈਫ਼ਨ ਹਨ, ਨਕਲੀ ਸਾਈਟਾਂ ਵਿੱਚ ਆਮ"),
    "no_https": ("Not a secure (https) connection", "सुरक्षित (https) कनेक्शन नहीं है", "ਸੁਰੱਖਿਅਤ (https) ਕੁਨੈਕਸ਼ਨ ਨਹੀਂ ਹੈ"),
    "brand_lookalike": ("Looks like a real bank or brand but is not its official site", "असली बैंक या ब्रांड जैसा दिखता है पर आधिकारिक साइट नहीं है", "ਅਸਲੀ ਬੈਂਕ ਜਾਂ ਬ੍ਰਾਂਡ ਵਰਗਾ ਦਿੱਸਦਾ ਹੈ ਪਰ ਅਧਿਕਾਰਤ ਸਾਈਟ ਨਹੀਂ"),
    "keyword_in_host": ("Address contains words like login, kyc or verify", "पते में login, kyc या verify जैसे शब्द हैं", "ਪਤੇ ਵਿੱਚ login, kyc ਜਾਂ verify ਵਰਗੇ ਸ਼ਬਦ ਹਨ"),
    "safe_browsing": ("Google Safe Browsing lists this link as dangerous", "Google Safe Browsing ने इस लिंक को खतरनाक बताया है", "Google Safe Browsing ਨੇ ਇਸ ਲਿੰਕ ਨੂੰ ਖ਼ਤਰਨਾਕ ਦੱਸਿਆ ਹੈ"),
    "new_domain": ("This website was created very recently", "यह वेबसाइट बहुत हाल ही में बनी है", "ਇਹ ਵੈੱਬਸਾਈਟ ਬਹੁਤ ਹਾਲ ਹੀ ਵਿੱਚ ਬਣੀ ਹੈ"),
}
_LI = {"en": 0, "hi": 1, "pa": 2}


def link_reason(key: str, lang: str) -> str:
    t = LINK_REASONS.get(key)
    return t[_LI.get(lang, 0)] if t else key.replace("_", " ")

NEXT_STEPS = {
    "scam": {
        "en": [
            "Do not click any link, open any file or reply.",
            "Never share your OTP, PIN or password with anyone.",
            "Block the sender and delete the message.",
            "If you already shared details or lost money, call 1930 right now.",
        ],
        "hi": [
            "कोई लिंक न खोलें, कोई फाइल न खोलें और जवाब न दें।",
            "अपना OTP, PIN या पासवर्ड किसी को न बताएं।",
            "भेजने वाले को ब्लॉक करें और मैसेज डिलीट करें।",
            "अगर जानकारी बता दी हो या पैसे कट गए हों तो अभी 1930 पर कॉल करें।",
        ],
        "pa": [
            "ਕੋਈ ਲਿੰਕ ਜਾਂ ਫਾਈਲ ਨਾ ਖੋਲ੍ਹੋ ਅਤੇ ਜਵਾਬ ਨਾ ਦਿਓ।",
            "ਆਪਣਾ OTP, PIN ਜਾਂ ਪਾਸਵਰਡ ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ।",
            "ਭੇਜਣ ਵਾਲੇ ਨੂੰ ਬਲੌਕ ਕਰੋ ਅਤੇ ਮੈਸੇਜ ਡਿਲੀਟ ਕਰੋ।",
            "ਜੇ ਜਾਣਕਾਰੀ ਦੱਸ ਦਿੱਤੀ ਹੋਵੇ ਜਾਂ ਪੈਸੇ ਕੱਟ ਗਏ ਹੋਣ ਤਾਂ ਹੁਣੇ 1930 ਤੇ ਕਾਲ ਕਰੋ।",
        ],
    },
    "suspicious": {
        "en": [
            "Do not click links or share personal details yet.",
            "Check with the real bank, office or person using a number you already know.",
            "Ask a family member before you do anything.",
            "If it turns out to be fake, report it using the steps below.",
        ],
        "hi": [
            "अभी लिंक न खोलें और निजी जानकारी न दें।",
            "जो नंबर आपके पास पहले से है उस पर असली बैंक, दफ्तर या व्यक्ति से पूछ लें।",
            "कुछ करने से पहले परिवार के किसी सदस्य से पूछें।",
            "नकली निकले तो नीचे दिए तरीके से शिकायत करें।",
        ],
        "pa": [
            "ਹਾਲੇ ਲਿੰਕ ਨਾ ਖੋਲ੍ਹੋ ਅਤੇ ਨਿੱਜੀ ਜਾਣਕਾਰੀ ਨਾ ਦਿਓ।",
            "ਜੋ ਨੰਬਰ ਤੁਹਾਡੇ ਕੋਲ ਪਹਿਲਾਂ ਤੋਂ ਹੈ, ਉਸ ਤੇ ਅਸਲੀ ਬੈਂਕ, ਦਫ਼ਤਰ ਜਾਂ ਵਿਅਕਤੀ ਤੋਂ ਪੁੱਛ ਲਓ।",
            "ਕੁਝ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਪਰਿਵਾਰ ਦੇ ਕਿਸੇ ਮੈਂਬਰ ਤੋਂ ਪੁੱਛੋ।",
            "ਨਕਲੀ ਨਿਕਲੇ ਤਾਂ ਹੇਠਾਂ ਦਿੱਤੇ ਤਰੀਕੇ ਨਾਲ ਸ਼ਿਕਾਇਤ ਕਰੋ।",
        ],
    },
    "safe": {
        "en": [
            "We found no warning signs, but stay careful.",
            "Never share your OTP or PIN, even if the message looks genuine.",
            "If anything feels odd, check again before you act.",
        ],
        "hi": [
            "हमें कोई खतरे का संकेत नहीं मिला, फिर भी सावधान रहें।",
            "संदेश असली लगे तब भी OTP या PIN किसी को न बताएं।",
            "कुछ अजीब लगे तो कदम उठाने से पहले दोबारा जांच लें।",
        ],
        "pa": [
            "ਸਾਨੂੰ ਕੋਈ ਖ਼ਤਰੇ ਦਾ ਸੰਕੇਤ ਨਹੀਂ ਮਿਲਿਆ, ਫਿਰ ਵੀ ਸਾਵਧਾਨ ਰਹੋ।",
            "ਸੁਨੇਹਾ ਅਸਲੀ ਲੱਗੇ ਤਾਂ ਵੀ OTP ਜਾਂ PIN ਕਿਸੇ ਨੂੰ ਨਾ ਦੱਸੋ।",
            "ਕੁਝ ਅਜੀਬ ਲੱਗੇ ਤਾਂ ਕੁਝ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਦੁਬਾਰਾ ਜਾਂਚ ਲਓ।",
        ],
    },
}

VERDICT_HEADLINE = {
    "scam": {"en": "This looks like a scam", "hi": "यह ठगी लगती है", "pa": "ਇਹ ਠੱਗੀ ਲੱਗਦੀ ਹੈ"},
    "suspicious": {"en": "This looks suspicious", "hi": "यह संदिग्ध लगता है", "pa": "ਇਹ ਸ਼ੱਕੀ ਲੱਗਦਾ ਹੈ"},
    "safe": {"en": "No scam signs found", "hi": "ठगी के संकेत नहीं मिले", "pa": "ਠੱਗੀ ਦੇ ਸੰਕੇਤ ਨਹੀਂ ਮਿਲੇ"},
}

# Where and how to report. Contacts are the official Indian channels.
REPORT = {
    "helpline": {"label": "National Cyber Crime Helpline", "value": "1930"},
    "portal": {"label": "Cyber Crime Portal", "value": "https://cybercrime.gov.in"},
    "sanchar": {"label": "Report suspicious calls/SMS/WhatsApp (Sanchar Saathi, Chakshu)", "value": "https://sancharsaathi.gov.in"},
    "steps": {
        "en": [
            "Money lost? Call 1930 immediately. The first hour matters most.",
            "File a complaint at cybercrime.gov.in with screenshots, the sender's number and any transaction ID.",
            "Tell your bank at once so it can freeze the transaction.",
            "In WhatsApp, tap the sender, then Report and Block.",
            "Do not delete the message until your complaint is filed.",
        ],
        "hi": [
            "पैसे कट गए? तुरंत 1930 पर कॉल करें। पहला घंटा सबसे ज़रूरी है।",
            "cybercrime.gov.in पर स्क्रीनशॉट, भेजने वाले का नंबर और ट्रांज़ैक्शन ID के साथ शिकायत करें।",
            "तुरंत अपने बैंक को बताएं ताकि वह लेन-देन रोक सके।",
            "WhatsApp में भेजने वाले पर टैप करें, फिर Report और Block करें।",
            "शिकायत दर्ज होने तक मैसेज डिलीट न करें।",
        ],
        "pa": [
            "ਪੈਸੇ ਕੱਟ ਗਏ? ਤੁਰੰਤ 1930 ਤੇ ਕਾਲ ਕਰੋ। ਪਹਿਲਾ ਘੰਟਾ ਸਭ ਤੋਂ ਜ਼ਰੂਰੀ ਹੈ।",
            "cybercrime.gov.in ਤੇ ਸਕਰੀਨਸ਼ਾਟ, ਭੇਜਣ ਵਾਲੇ ਦੇ ਨੰਬਰ ਅਤੇ ਟ੍ਰਾਂਜ਼ੈਕਸ਼ਨ ID ਨਾਲ ਸ਼ਿਕਾਇਤ ਕਰੋ।",
            "ਤੁਰੰਤ ਆਪਣੇ ਬੈਂਕ ਨੂੰ ਦੱਸੋ ਤਾਂ ਜੋ ਉਹ ਲੈਣ-ਦੇਣ ਰੋਕ ਸਕੇ।",
            "WhatsApp ਵਿੱਚ ਭੇਜਣ ਵਾਲੇ ਤੇ ਟੈਪ ਕਰੋ, ਫਿਰ Report ਅਤੇ Block ਕਰੋ।",
            "ਸ਼ਿਕਾਇਤ ਦਰਜ ਹੋਣ ਤੱਕ ਮੈਸੇਜ ਡਿਲੀਟ ਨਾ ਕਰੋ।",
        ],
    },
}


def _t(d: dict, lang: str) -> str | list:
    return d.get(lang) or d["en"]


def build(analysis) -> dict:
    """Return the full, user-facing explanation for an Analysis."""
    lang = analysis.lang if analysis.lang in ("en", "hi", "pa") else "en"
    why: list[str] = []
    for cat in analysis.categories:
        if cat in WHY:
            why.append(_t(WHY[cat], lang))
    link_notes: list[str] = []
    for link in analysis.links:
        if link.reasons:
            link_notes.append(f"{link.host}: " + "; ".join(link_reason(r, lang) for r in link.reasons))
    return {
        "headline": _t(VERDICT_HEADLINE[analysis.verdict], lang),
        "summary": analysis.reason,
        "why": why,
        "link_notes": link_notes,
        "next_steps": _t(NEXT_STEPS[analysis.verdict], lang),
        "report": {
            "show": analysis.verdict in ("scam", "suspicious"),
            "helpline": REPORT["helpline"],
            "portal": REPORT["portal"],
            "sanchar": REPORT["sanchar"],
            "steps": _t(REPORT["steps"], lang),
        },
    }
