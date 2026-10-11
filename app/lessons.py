"""'Scam of the Day' micro-lessons in English, Hindi and Punjabi (short enough to read aloud)."""
from __future__ import annotations

import datetime as dt

LESSONS: list[dict[str, str]] = [
    {
        "en": "FAKE KYC CALL. A 'bank officer' says your KYC is expired and your account will be blocked. Banks never update KYC over phone, SMS links or WhatsApp. Hang up and visit your branch.",
        "hi": "नकली KYC कॉल। कोई 'बैंक अधिकारी' कहता है कि KYC खत्म हो गई और खाता बंद होगा। बैंक फोन, SMS लिंक या WhatsApp से KYC अपडेट नहीं करते। फोन काट दें और अपनी शाखा में जाएं।",
        "pa": "ਨਕਲੀ KYC ਕਾਲ। ਕੋਈ 'ਬੈਂਕ ਅਫ਼ਸਰ' ਕਹਿੰਦਾ ਹੈ ਕਿ KYC ਖ਼ਤਮ ਹੋ ਗਈ ਤੇ ਖਾਤਾ ਬੰਦ ਹੋਵੇਗਾ। ਬੈਂਕ ਫੋਨ, SMS ਲਿੰਕ ਜਾਂ WhatsApp ਰਾਹੀਂ KYC ਅਪਡੇਟ ਨਹੀਂ ਕਰਦੇ। ਫੋਨ ਕੱਟ ਦਿਓ ਤੇ ਆਪਣੀ ਸ਼ਾਖਾ ਜਾਓ।",
    },
    {
        "en": "OTP IS A KEY. Whoever has your OTP can open your bank account. No bank, police officer or company will ever ask for it. Never tell it to anyone, even if they sound polite.",
        "hi": "OTP आपकी चाबी है। जिसके पास OTP है, वह आपका खाता खोल सकता है। कोई बैंक, पुलिस या कंपनी इसे नहीं मांगती। मीठा बोलने वाले को भी OTP न बताएं।",
        "pa": "OTP ਤੁਹਾਡੀ ਚਾਬੀ ਹੈ। ਜਿਸ ਕੋਲ OTP ਹੈ, ਉਹ ਤੁਹਾਡਾ ਖਾਤਾ ਖੋਲ੍ਹ ਸਕਦਾ ਹੈ। ਕੋਈ ਬੈਂਕ, ਪੁਲਿਸ ਜਾਂ ਕੰਪਨੀ ਇਹ ਨਹੀਂ ਮੰਗਦੀ। ਮਿੱਠਾ ਬੋਲਣ ਵਾਲੇ ਨੂੰ ਵੀ OTP ਨਾ ਦੱਸੋ।",
    },
    {
        "en": "RECEIVING MONEY NEEDS NO PIN. If someone says 'enter your UPI PIN to receive money' or sends a collect request to 'refund' you, they are taking money out of your account. Decline it.",
        "hi": "पैसे पाने के लिए PIN नहीं डालना पड़ता। अगर कोई कहे 'पैसे लेने के लिए UPI PIN डालें' या 'रिफंड' के नाम पर कलेक्ट रिक्वेस्ट भेजे, तो वह आपके खाते से पैसे निकाल रहा है। उसे रिजेक्ट करें।",
        "pa": "ਪੈਸੇ ਲੈਣ ਲਈ PIN ਨਹੀਂ ਪਾਉਣਾ ਪੈਂਦਾ। ਜੇ ਕੋਈ ਕਹੇ 'ਪੈਸੇ ਲੈਣ ਲਈ UPI PIN ਪਾਓ' ਜਾਂ 'ਰਿਫੰਡ' ਦੇ ਨਾਮ ਤੇ ਕੁਲੈਕਟ ਰਿਕੁਐਸਟ ਭੇਜੇ, ਤਾਂ ਉਹ ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚੋਂ ਪੈਸੇ ਕੱਢ ਰਿਹਾ ਹੈ। ਇਸਨੂੰ ਰੱਦ ਕਰੋ।",
    },
    {
        "en": "LOTTERY YOU NEVER ENTERED. 'You won 25 lakh in KBC!' If you never bought a ticket, you cannot win. Anyone asking a 'processing fee' to release a prize is a thief.",
        "hi": "जिस लॉटरी में हिस्सा नहीं लिया। 'आपने KBC में 25 लाख जीते!' अगर टिकट खरीदा ही नहीं, तो इनाम नहीं मिल सकता। इनाम के लिए 'प्रोसेसिंग फीस' मांगने वाला ठग है।",
        "pa": "ਜਿਸ ਲਾਟਰੀ ਵਿੱਚ ਹਿੱਸਾ ਨਹੀਂ ਲਿਆ। 'ਤੁਸੀਂ KBC ਵਿੱਚ 25 ਲੱਖ ਜਿੱਤੇ!' ਜੇ ਟਿਕਟ ਖਰੀਦੀ ਹੀ ਨਹੀਂ, ਤਾਂ ਇਨਾਮ ਨਹੀਂ ਮਿਲ ਸਕਦਾ। ਇਨਾਮ ਲਈ 'ਪ੍ਰੋਸੈਸਿੰਗ ਫੀਸ' ਮੰਗਣ ਵਾਲਾ ਠੱਗ ਹੈ।",
    },
    {
        "en": "DIGITAL ARREST. A caller in 'police' or 'CBI' uniform on video says you are under arrest and must stay on the call and pay. There is no such thing as digital arrest. Cut the call and dial 1930.",
        "hi": "डिजिटल अरेस्ट। वीडियो कॉल पर 'पुलिस' या 'CBI' की वर्दी में कोई कहे कि आप गिरफ्तार हैं, कॉल पर रहें और पैसे भेजें। डिजिटल अरेस्ट जैसी कोई चीज़ नहीं होती। कॉल काटें और 1930 डायल करें।",
        "pa": "ਡਿਜੀਟਲ ਅਰੈਸਟ। ਵੀਡੀਓ ਕਾਲ ਤੇ 'ਪੁਲਿਸ' ਜਾਂ 'CBI' ਦੀ ਵਰਦੀ ਵਿੱਚ ਕੋਈ ਕਹੇ ਕਿ ਤੁਸੀਂ ਗ੍ਰਿਫ਼ਤਾਰ ਹੋ, ਕਾਲ ਤੇ ਰਹੋ ਤੇ ਪੈਸੇ ਭੇਜੋ। ਡਿਜੀਟਲ ਅਰੈਸਟ ਵਰਗੀ ਕੋਈ ਚੀਜ਼ ਨਹੀਂ ਹੁੰਦੀ। ਕਾਲ ਕੱਟੋ ਤੇ 1930 ਡਾਇਲ ਕਰੋ।",
    },
    {
        "en": "SCREEN-SHARING APPS. 'Install AnyDesk so we can fix your refund.' These apps let a stranger see your screen, PIN and OTP. Never install an app because a caller asks.",
        "hi": "स्क्रीन-शेयरिंग ऐप। 'रिफंड ठीक करने के लिए AnyDesk डालें।' इन ऐप से अनजान आदमी आपकी स्क्रीन, PIN और OTP देख लेता है। फोन करने वाले के कहने पर कोई ऐप न डालें।",
        "pa": "ਸਕ੍ਰੀਨ-ਸ਼ੇਅਰਿੰਗ ਐਪ। 'ਰਿਫੰਡ ਠੀਕ ਕਰਨ ਲਈ AnyDesk ਪਾਓ।' ਇਨ੍ਹਾਂ ਐਪਾਂ ਨਾਲ ਅਣਜਾਣ ਬੰਦਾ ਤੁਹਾਡੀ ਸਕ੍ਰੀਨ, PIN ਤੇ OTP ਵੇਖ ਲੈਂਦਾ ਹੈ। ਫੋਨ ਕਰਨ ਵਾਲੇ ਦੇ ਕਹਿਣ ਤੇ ਕੋਈ ਐਪ ਨਾ ਪਾਓ।",
    },
    {
        "en": "FAKE ELECTRICITY CUT. 'Your power will be cut tonight, call this number.' The electricity board does not disconnect through a WhatsApp message. Check your bill on the official website or office.",
        "hi": "बिजली कटने का झूठा मैसेज। 'आज रात बिजली कट जाएगी, इस नंबर पर कॉल करें।' बिजली विभाग WhatsApp मैसेज से कनेक्शन नहीं काटता। अपना बिल आधिकारिक वेबसाइट या दफ्तर में जांचें।",
        "pa": "ਬਿਜਲੀ ਕੱਟਣ ਦਾ ਝੂਠਾ ਮੈਸੇਜ। 'ਅੱਜ ਰਾਤ ਬਿਜਲੀ ਕੱਟ ਦਿੱਤੀ ਜਾਵੇਗੀ, ਇਸ ਨੰਬਰ ਤੇ ਕਾਲ ਕਰੋ।' ਬਿਜਲੀ ਵਿਭਾਗ WhatsApp ਮੈਸੇਜ ਨਾਲ ਕੁਨੈਕਸ਼ਨ ਨਹੀਂ ਕੱਟਦਾ। ਆਪਣਾ ਬਿੱਲ ਸਰਕਾਰੀ ਵੈੱਬਸਾਈਟ ਜਾਂ ਦਫ਼ਤਰ ਵਿੱਚ ਜਾਂਚੋ।",
    },
    {
        "en": "FIRST HOUR MATTERS. If money is gone, call 1930 immediately and report at cybercrime.gov.in. Banks can often freeze the money if you act within the first hour. Do not feel ashamed; anyone can be fooled.",
        "hi": "पहला घंटा सबसे जरूरी है। पैसे कट जाएं तो तुरंत 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत करें। पहले घंटे में बैंक अक्सर पैसा रोक सकता है। शर्म न करें, ठगी किसी के साथ भी हो सकती है।",
        "pa": "ਪਹਿਲਾ ਘੰਟਾ ਸਭ ਤੋਂ ਜ਼ਰੂਰੀ ਹੈ। ਪੈਸੇ ਕੱਟ ਜਾਣ ਤਾਂ ਤੁਰੰਤ 1930 ਤੇ ਕਾਲ ਕਰੋ ਤੇ cybercrime.gov.in ਤੇ ਸ਼ਿਕਾਇਤ ਕਰੋ। ਪਹਿਲੇ ਘੰਟੇ ਵਿੱਚ ਬੈਂਕ ਅਕਸਰ ਪੈਸਾ ਰੋਕ ਸਕਦਾ ਹੈ। ਸ਼ਰਮ ਨਾ ਕਰੋ, ਠੱਗੀ ਕਿਸੇ ਨਾਲ ਵੀ ਹੋ ਸਕਦੀ ਹੈ।",
    },
]


def lesson_for(day: dt.date | None = None) -> dict[str, str]:
    day = day or dt.date.today()
    return LESSONS[day.toordinal() % len(LESSONS)]


def lesson_text(lang: str, day: dt.date | None = None) -> str:
    lesson = lesson_for(day)
    return lesson.get(lang) or lesson["en"]
