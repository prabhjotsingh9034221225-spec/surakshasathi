"""Labelled sample messages used by the tests and handy for demos.

SCAMS must be classified 'scam'; SUSPICIOUS may be 'suspicious' or 'scam'; SAFE must not be 'scam'.
"""

SCAMS = [
    # fake KYC / account block
    "Dear customer, your SBI account is blocked. Update KYC immediately: http://sbi-kyc-update.xyz/login",
    "Your HDFC Bank account will be suspended today. Complete your KYC now by clicking https://hdfc-verify.top/kyc",
    "आपका SBI खाता बंद हो जाएगा। तुरंत KYC अपडेट करें और OTP बताएं।",
    "SBI ka account band ho jayega, turant OTP bhejo",
    "ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ। ਤੁਰੰਤ KYC ਅਪਡੇਟ ਕਰੋ ਅਤੇ OTP ਦੱਸੋ।",
    "Your PAN card will be blocked. Update PAN immediately at http://incometax-pan.click/update",
    # OTP / PIN theft
    "Sir I am calling from bank, please share the OTP you just received to cancel the transaction",
    "Please send your ATM PIN and CVV to verify your card",
    "अपना UPI पिन बताइए ताकि आपका रिफंड हो सके",
    # UPI collect
    "Approve the collect request and enter your UPI PIN to receive your Rs 5000 refund",
    "पैसे पाने के लिए अपना UPI पिन डालें, रिफंड तुरंत मिलेगा",
    # lottery / prize
    "Congratulations! You won Rs 25,00,000 in KBC lottery. Pay processing fee Rs 5000 to claim your prize",
    "बधाई हो! आपने 25 लाख की लॉटरी जीती है। इनाम पाने के लिए प्रोसेसिंग फीस जमा करें।",
    "ਵਧਾਈ ਹੋਵੇ! ਤੁਸੀਂ ਲਾਟਰੀ ਜਿੱਤੀ ਹੈ। ਇਨਾਮ ਲਈ ਪ੍ਰੋਸੈਸਿੰਗ ਫੀਸ ਜਮ੍ਹਾ ਕਰੋ।",
    # electricity
    "Dear consumer, your electricity power will be disconnected tonight 9:30 pm because your bill is not updated. Call 98xxxxxx immediately",
    "ਤੁਹਾਡਾ ਬਿਜਲੀ ਕੁਨੈਕਸ਼ਨ ਅੱਜ ਰਾਤ ਕੱਟ ਦਿੱਤਾ ਜਾਵੇਗਾ। ਬਿੱਲ ਅਪਡੇਟ ਕਰੋ।",
    "आपका बिजली कनेक्शन आज रात कट जाएगा, बिल अपडेट करें",
    # digital arrest / courier
    "This is CBI. A parcel with illegal drugs was found in your name. You are under digital arrest, stay on the video call and pay the fine",
    "Your courier parcel is held at customs. Pay customs fee Rs 3500 to release it today",
    # remote access / apk
    "Install AnyDesk so our executive can help you get your refund",
    "Download this app to claim your reward: http://claim-gift.site/reward.apk",
    # jobs / investment
    "Work from home part time job, earn Rs 5000 per day just by liking YouTube videos. Pay registration fee Rs 500",
    "Guaranteed returns! Double your money in 30 days with our crypto trading tips group",
]

SUSPICIOUS_OK = [
    "Galti se aapke account me 10000 rupaye aa gaye hain, please wapas bhej do",
    "Your KYC is pending, please update it at your nearest branch",
    "You have won a free gift voucher",
]

SAFE = [
    "Hi beta, dinner at 8 today? Please bring milk on the way.",
    "Your OTP is 482913. Do not share it with anyone. -HDFC Bank",
    "आपका OTP 482913 है। इसे किसी को न बताएं। -SBI",
    "Your Amazon order has been shipped and will arrive tomorrow. Track at https://www.amazon.in/orders",
    "Rs 500 debited from your A/c XX1234 on 10-Oct. Not you? Call your bank helpline.",
    "Reminder: your electricity bill of Rs 1,240 is due on 15 Oct. Pay through the official app or office.",
    "Meeting moved to 4pm. See you at the gurdwara after.",
    "ਸਤ ਸ੍ਰੀ ਅਕਾਲ ਜੀ, ਕੱਲ੍ਹ ਪਿੰਡ ਆ ਰਹੇ ਹਾਂ।",
    "Doctor appointment confirmed for Monday 10:30 am at the civil hospital.",
    "Happy Diwali to you and your family! 🪔",
]
