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


# ---------------------------------------------------------------------------
# Second, harder corpus. Written BEFORE the detector was tuned for it, so the first
# measurement on it is an honest hold-out number. Real-world Indian scam patterns.
# ---------------------------------------------------------------------------
SCAMS_V2 = [
    # WhatsApp / account takeover
    "Hi, I accidentally sent my 6 digit code to your number, please forward it to me urgently",
    "Your WhatsApp will be deactivated in 24 hours. Verify your account by sharing the code sent by SMS",
    # QR / UPI
    "Scan this QR code to receive Rs 2000 in your account, enter your UPI PIN to confirm",
    "Aapko cashback milega, QR scan karo aur PIN dalo",
    "Your friend sent you money request, click here and enter UPI PIN to accept: http://upi-collect-pay.top/accept",
    # government / tax / telecom
    "Income Tax refund of Rs 15,490 approved. Submit your bank details at http://incometax-refund.top/claim to receive it",
    "Your SIM card will be blocked in 2 hours. Call 9876543210 now to complete KYC verification",
    "Aadhaar update required, your Aadhaar will be deactivated. Click http://uidai-update.click/aadhaar",
    "आपका आधार कार्ड बंद हो जाएगा, तुरंत लिंक पर क्लिक करके अपडेट करें",
    "Pending e-challan of Rs 500 on your vehicle. Pay now at http://echallan-pay.xyz or face legal action",
    "FASTag KYC expired, your FASTag will be blocked. Update now at http://fastag-kyc.top",
    "PM Kisan yojana ka paisa aapke account me aane wala hai, apna bank detail aur OTP bhejo",
    "Gas subsidy of Rs 1200 is pending, update your bank details with this link to receive it",
    # loan / investment / task
    "Instant loan approved Rs 50,000 without documents. Pay Rs 1500 processing fee to release the amount",
    "Join our VIP trading group, 300% profit guaranteed in 7 days. Invest Rs 10,000 and withdraw Rs 30,000",
    "Task job: like and subscribe, earn Rs 800 per task. Deposit Rs 1000 to start, you will get it back with commission",
    "Congratulations you are selected for Amazon work from home job, salary Rs 40,000. Pay Rs 999 for ID card",
    "Bitcoin investment, daily returns 10%, contact our manager on Telegram now",
    # impersonation / calls
    "This is customer care of your bank. Your card is blocked, tell us the card number and CVV to unblock",
    "Main police station se bol raha hu, aapke naam par case hai, abhi paise bhejo warna giraftari hogi",
    "ED officer here. Your Aadhaar is linked to money laundering. Do not disconnect the call or tell anyone",
    "TRAI notice: your mobile number will be disconnected for illegal activity. Press 1 to talk to officer",
    "Beta main tera uncle bol raha hu, naya number hai, abhi 20000 bhej do, emergency hai, kisi ko mat batana",
    "Mom I lost my phone, this is my new number, please send Rs 15000 urgently to this account",
    # sextortion / threats
    "We have your private video. Pay Rs 20,000 in 1 hour or we will send it to all your contacts",
    # courier / electricity / delivery
    "FedEx: your parcel has drugs, Mumbai cyber crime branch will call you. Do not tell anyone, stay on the line",
    "Your package could not be delivered. Pay Rs 49 redelivery fee at http://india-post-track.top/pay",
    "Dear customer your electricity bill is unpaid, connection will be cut tonight. Contact officer 9123456780 immediately",
    # KYC variants in other languages
    "आपका PAN कार्ड ब्लॉक हो गया है, अभी अपडेट करें वरना खाता बंद हो जाएगा http://pan-update.top",
    "ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਬਲੌਕ ਹੋ ਗਿਆ ਹੈ, ਤੁਰੰਤ ਲਿੰਕ ਤੇ ਕਲਿੱਕ ਕਰਕੇ KYC ਕਰੋ",
    "ਤੁਹਾਨੂੰ 10 ਲੱਖ ਦਾ ਇਨਾਮ ਲੱਗਿਆ ਹੈ, ਟੈਕਸ ਭਰਨ ਲਈ ਪੈਸੇ ਭੇਜੋ",
    "Aapka bijli ka connection aaj raat kat jayega, is number par turant call karein",
    "Sir aapka credit card reward points expire ho rahe hain, apna OTP batao redeem karne ke liye",
    "Download this app to update your KYC: https://bank-secure-kyc.top/update.apk",
    "Install TeamViewer QuickSupport and tell me the 9 digit ID so I can fix your bank issue",
    "Your Netflix subscription is suspended. Update payment at http://netflix-billing-update.xyz now",
    "You have won an iPhone 15 in Flipkart lucky draw. Pay delivery charge Rs 299 to claim today",
    "Dear user, KBC lucky winner Rs 25 lakh, WhatsApp 9876501234 and pay registration fee",
    "Verify your account now or it will be closed permanently: http://secure-login-sbi.click",
    "Hello sir, refund for your wrong transaction is pending, share the OTP and last 4 digits of your debit card",
    "Hey, I'm stuck abroad, lost my wallet, please transfer Rs 25,000 to this UPI, will return tomorrow, don't call",
    "Free recharge for 1 year! Click and enter your number and PIN: http://jio-free-recharge.top",
    "Please pay Rs 2 to verify your Paytm KYC and avoid account suspension",
]

SAFE_V2 = [
    "Your OTP for login is 556677. It is valid for 10 minutes. Never share this OTP with anyone.",
    "Rs 1,250.00 credited to your A/c XX4521 on 12-Nov by UPI. Available balance Rs 8,402. -ICICI Bank",
    "Your Swiggy order is out for delivery. Delivery partner will call you. Enjoy your meal!",
    "Your electricity bill for October is Rs 1,840, due 20 Nov. Pay on the official portal or at the office.",
    "Hi, this is Dr Sharma's clinic. Your appointment is confirmed for tomorrow at 11 am.",
    "Beta, I reached home safe. Call me when you are free.",
    "ਕੱਲ੍ਹ ਗੁਰਦੁਆਰੇ ਚੱਲਣਾ ਹੈ, ਸਵੇਰੇ ਅੱਠ ਵਜੇ ਤਿਆਰ ਰਹਿਣਾ।",
    "कल शाम को घर आना, खाना साथ में खाएंगे।",
    "Aaj raat dinner ke liye bahar chalte hain? Papa ne bhi bulaya hai.",
    "Reminder: your LIC premium of Rs 5,000 is due on 30 Nov. Pay via your LIC app or branch.",
    "Your Amazon package was delivered. Rate your experience in the app.",
    "IRCTC: Your ticket PNR 2345678901 is confirmed. Coach S4, seat 22. Happy journey!",
    "Never share your OTP, PIN or CVV with anyone. Banks never ask for them. Stay safe. -SBI",
    "आपके खाते से Rs 200 डेबिट हुए हैं। अगर आपने नहीं किए तो बैंक हेल्पलाइन पर कॉल करें।",
    "Your Jio recharge of Rs 299 is successful. Validity 28 days. Thank you for choosing Jio.",
    "Meeting rescheduled to Friday 3 pm. Please confirm if it works for you.",
    "Congratulations on your daughter's wedding! Wishing the couple a lifetime of happiness.",
    "Your Zomato refund of Rs 180 has been processed to your original payment method.",
    "School notice: PTM on Saturday 10 am. Parents are requested to attend.",
    "Happy birthday bhai! Party kab de raha hai? 🎂",
    "Please carry your Aadhaar card and original documents when you visit the bank branch on Monday.",
    "Your Google verification code is 482 913. Don't share this code with anyone.",
    "Hello, I am calling about the flat you listed for rent. Is it still available?",
    "Dear customer, your gas cylinder has been booked and will be delivered on 15 Nov. Pay on delivery to the delivery person only.",
    "Mausi ji ki tabiyat theek hai ab, doctor ne kal ghar bhej diya.",
]


# ---------------------------------------------------------------------------
# Third corpus: a fresh hold-out. Measured ONCE before any tuning for it, to report an honest
# generalisation number. (Afterwards it joins the regression set like the others.)
# ---------------------------------------------------------------------------
SCAMS_V3 = [
    "Dear SBI user, your YONO account is temporarily locked due to incomplete verification. Reactivate at http://yono-sbi-login.top",
    "Congratulations!! Your mobile number has won Rs 10,00,000 in Jio Lucky Draw. Call 9988776655 to claim",
    "We noticed unusual login on your Amazon account. Confirm your identity with the 6 digit code we are about to send",
    "Sir, I am from LIC head office. Your policy bonus Rs 80,000 is ready, share your bank account number and OTP to credit it",
    "Hello, this is Amazon customer support. We sent you a refund by mistake, please install the Quick Support app so we can reverse it",
    "Hiring: online product reviewer. Earn Rs 3000 daily from home. Register with Rs 500 deposit, refundable",
    "Your electricity meter KYC is pending. Power supply will be stopped from 9 pm. Call our engineer 8899001122 now",
    "Your Aadhaar is linked to a SIM used in illegal activity. Call the cyber cell number immediately or you will be arrested",
    "Dear customer, a payment of Rs 49,999 is being made from your account. If it is not you, call 7766554433 immediately",
    "आपके खाते से 49,999 रुपये निकाले जा रहे हैं, रोकने के लिए तुरंत इस नंबर पर कॉल करें और अपना OTP बताएं",
    "आपको पीएम योजना के तहत 2 लाख रुपये मिलेंगे, इसके लिए अपना बैंक खाता नंबर और पिन भेजें",
    "ਤੁਹਾਡਾ ਆਧਾਰ ਕਾਰਡ ਬਲੌਕ ਹੋਣ ਵਾਲਾ ਹੈ, ਹੁਣੇ ਇਸ ਲਿੰਕ ਤੇ ਕਲਿੱਕ ਕਰੋ ਅਤੇ ਜਾਣਕਾਰੀ ਭਰੋ",
    "ਤੁਹਾਡੇ ਬੈਂਕ ਖਾਤੇ ਵਿੱਚੋਂ ਪੈਸੇ ਕੱਟੇ ਗਏ ਹਨ, ਵਾਪਸੀ ਲਈ ਆਪਣਾ OTP ਦੱਸੋ",
    "Bhai mera phone kharab ho gaya, ye mera naya number hai. Ek urgent kaam hai, 30000 PhonePe kar do, kal wapas",
    "Sir, your Paytm wallet KYC has expired. Wallet will be frozen in 2 hours. Update here: http://paytm-kyc-verify.click",
    "Win a free iPhone! Just pay Rs 99 shipping and enter your card number and CVV to claim your prize",
    "You are required to pay Rs 5,000 customs duty to release your gift package from UK. Send to UPI id customs@okaxis",
    "Part-time work: rate hotels on Google Maps, earn Rs 200 per rating. Join our Telegram group to start",
    "Dear investor, our AI trading bot gives 5% daily profit. Minimum investment Rs 5000. Withdraw anytime. Join now",
    "Your credit card limit has been increased to Rs 5 lakh. To activate, share the OTP sent to your mobile",
    "Madam your gas connection will be cancelled tomorrow due to incomplete e-KYC. Call 9090909090 to avoid cancellation",
    "I am Major Singh of Indian Army, posted in Ladakh. I want to sell my bike cheap, pay advance Rs 5000 to book",
    "Verify your SBI card rewards now or lose Rs 9,980 points today: http://sbi-rewards-claim.top",
    "Your LPG subsidy has not been credited. Share the 4 digit PIN you receive by SMS so we can release it",
    "Hello, this is Microsoft support. Your computer has a virus. Let me connect remotely using AnyDesk to remove it",
    "You are summoned by the High Court. A case of cheque bounce is filed against you. Pay Rs 7,500 settlement today to avoid arrest",
    "We are calling from Mumbai Police. Your son is in custody. Transfer Rs 50,000 immediately for his bail, do not tell anyone",
    "Free Netflix for 1 year for all Airtel users. Click now and enter your mobile number and OTP to get it: http://free-netflix-airtel.top",
    "Bank notice: Your debit card has been blocked. To unblock, send your card number, expiry date and CVV to this WhatsApp number",
    "बिजली बिल जमा नहीं हुआ है, आज रात 10 बजे कनेक्शन कट जाएगा। तुरंत अधिकारी से बात करें 9876012345",
    "Aapka KYC expire ho gaya hai, ab aapka account band ho jayega. Link par click karke update karein: bit.ly/kyc-now",
    "Amazon Prime se refund ke liye ye link kholein aur apna card detail dalein: http://amazon-refund-india.top",
    "Your parcel from Dubai is held at Delhi airport. Pay Rs 8,500 clearance charge immediately to release it",
    "Dear sir, you've been selected for a government job, pay Rs 2,000 for medical and registration to confirm joining",
    "Aapke naam se ek courier pakda gaya hai jisme MDMA mila hai. Mumbai police aapse video call par baat karegi, call kaatna mat",
    "HDFC: Your netbanking will be blocked today. Update PAN now https://hdfc-pan-update.top to continue",
    "ਤੁਹਾਡਾ ਪਾਰਸਲ ਕਸਟਮ ਵਿੱਚ ਰੁਕਿਆ ਹੋਇਆ ਹੈ, ਛੱਡਣ ਲਈ 4500 ਰੁਪਏ ਫੀਸ ਭਰੋ",
    "Respected sir, your son has met with an accident. Please send Rs 25000 urgently to this account for surgery",
    "Claim your cashback of Rs 750: open Google Pay, tap the request and enter your UPI PIN",
    "Last warning: your SIM card number will be permanently blocked today as per DOT rules. Verify Aadhaar now http://dot-verify.top",
    "Make money online: invest Rs 2000 and get Rs 10,000 in 3 days guaranteed. Telegram: @quickprofit",
]

SAFE_V3 = [
    "Your OTP is 903821 for logging in to Flipkart. Do not share this with anyone.",
    "SBI: Rs 4,500 withdrawn from A/c XX8821 at ATM on 18-Nov. If not you, call 1800 1234 immediately.",
    "Dear customer, your Airtel bill of Rs 599 is generated. Pay by 25 Nov via the Airtel Thanks app.",
    "Your Uber ride is arriving in 3 minutes. Driver: Ramesh, vehicle PB10 AB 1234.",
    "Hi, I'll be late today, traffic is heavy. Please start dinner without me.",
    "Namaste, your appointment with the dentist is tomorrow at 5 pm. Reply YES to confirm.",
    "ਸਤ ਸ੍ਰੀ ਅਕਾਲ, ਕੱਲ੍ਹ ਮੀਟਿੰਗ ਸਵੇਰੇ ਦਸ ਵਜੇ ਹੈ, ਸਮੇਂ ਸਿਰ ਪਹੁੰਚਣਾ।",
    "आपका बिजली बिल 1,150 रुपये है, अंतिम तिथि 28 नवंबर। भुगतान आधिकारिक ऐप या कार्यालय में करें।",
    "Congratulations on your promotion! Proud of you. Party this weekend?",
    "Your passport application has been received. Track the status on the official Passport Seva portal.",
    "Bhaiya kal ghar aa jao, mummy ne kheer banayi hai.",
    "HDFC Bank: Never share your OTP, PIN or CVV with anyone, including bank staff.",
    "Your flight AI 202 departs at 6:45 am from Delhi. Web check-in is now open.",
    "Reminder: Payment of Rs 12,000 for your child's school fee is due on 5 Dec. Pay at the school office.",
    "Your Aadhaar enrolment centre appointment is on Monday 11 am. Please carry original documents.",
    "Mom, I reached the hostel. Phone battery is low, will call tomorrow.",
    "Your Myntra order #4432 has been delivered. We hope you love it!",
    "IT dept reminds taxpayers: the last date to file ITR is 31 July. File only on the official incometax.gov.in site.",
    "Hi, can you please send me the notes from yesterday's class when you get time?",
    "ਤੁਹਾਡੀ ਗੈਸ ਦੀ ਬੁਕਿੰਗ ਹੋ ਗਈ ਹੈ, ਸਿਲੰਡਰ ਕੱਲ੍ਹ ਪਹੁੰਚ ਜਾਵੇਗਾ।",
    "Your Paytm payment of Rs 220 to Sharma Medicals was successful.",
    "Beta, tu pahunch gaya? Pahunchte hi phone kar dena.",
    "Hello, this is the bank. This is a reminder that your fixed deposit matures next week. Please visit your branch with your ID.",
    "Dear customer, your new credit card has been dispatched and will arrive in 5-7 days. Activate it only in the official app.",
    "Sale! Flat 50% off on winter wear at our store this Sunday, 10 am to 8 pm.",
]


# ---------------------------------------------------------------------------
# Fourth corpus: fresh hold-out, written after the intent layer was built and measured before any
# tuning for it. Includes genuine messages that look scary (EMI, challan, job offers, friends asking for money).
# ---------------------------------------------------------------------------
SCAMS_V4 = [
    "Dear Customer, Your ICICI credit card reward points worth Rs 8,540 will expire today. Redeem now through this link: http://icici-rewardz.top/redeem",
    "Sir your Airtel postpaid number will be barred tonight due to KYC non-compliance. Call our executive on 9811122233 to avoid barring",
    "Urgent: Your PF account withdrawal of Rs 1,20,000 is approved. Share your UAN and OTP to receive the amount in your bank",
    "A warrant has been issued in your name by the Supreme Court. Contact Inspector Rathore on 9822211100 within 2 hours to settle the matter",
    "Hello ma'am, I am delivering your Amazon order but the address is incomplete. Share the OTP you got on SMS so I can confirm delivery, else order will be cancelled and money not refunded",
    "Your son has been caught with drugs in Bangalore. Pay Rs 1,50,000 to the officer right now to close the case, do not inform anyone",
    "Earn Rs 15,000 per week by just forwarding WhatsApp messages. Pay Rs 1,100 for activation and start today. Limited seats",
    "Congratulations, your Samsung Galaxy S24 is ready for delivery because you are the 1000th visitor. Pay Rs 399 for courier to confirm: http://galaxy-gift.click",
    "RBI is giving all account holders a Rs 5,000 compensation. Enter your account number and ATM PIN on the form here: http://rbi-compensation.top",
    "Mr Sharma, the property tax defaulters list has your name. Pay Rs 6,800 now via this UPI to remove it and avoid seizure: pt-dept@okicici",
    "Your Instagram account has copyright violation. It will be deleted in 12 hours. Appeal here and log in with your password: http://insta-appeal-help.top",
    "I am a doctor from Canada, I want to donate 5 million dollars to you. Send your bank details and pay Rs 20,000 for transfer paperwork",
    "Hello, congratulations. Your resume was shortlisted at TCS. To confirm your interview slot pay a refundable security deposit of Rs 3,500 on this number",
    "Sir, your electricity connection will be disconnected today at 8 pm as last month's bill is pending. Immediately call the officer: 9871234567",
    "Dear user your PhonePe account will be suspended. To avoid this share your UPI PIN and the 6 digit code we have sent to you",
    "Sell your old coins and notes for lakhs! Pay Rs 2,500 registration fee, buyers are waiting. Call 9900112233",
    "Beti, papa bol raha hu, phone gir gaya toh nayi SIM li hai. Abhi 40000 is account me daal do, hospital me bharti hu. Kisi ko mat batana",
    "ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਅੱਜ ਬੰਦ ਹੋ ਜਾਵੇਗਾ। ਜੇ ਤੁਸੀਂ ਇਸਨੂੰ ਬਚਾਉਣਾ ਚਾਹੁੰਦੇ ਹੋ ਤਾਂ ਇਸ ਨੰਬਰ ਤੇ ਕਾਲ ਕਰੋ 9876543211 ਅਤੇ ਆਪਣਾ ਪਿੰਨ ਦੱਸੋ",
    "आपके नाम पर 5 लाख का लोन पास हुआ है। पैसे लेने के लिए पहले 2,500 रुपये इंश्योरेंस फीस जमा करें और इस नंबर पर संपर्क करें 9812345670",
    "आपकी पार्सल डिलीवरी रुकी हुई है। 49 रुपये का भुगतान करने के लिए इस लिंक पर क्लिक करें http://post-delivery.top",
    "Bhai crypto me paisa lagao, 3 din me double hoga. Mere pe bharosa rakho, 10000 bhej do abhi, screenshot bhejna",
    "Your Gpay account got Rs 10,000 reward. To accept it open the request from 'Gpay rewards' and enter your UPI PIN. Offer ends in 30 minutes",
    "Hello sir, this is from Jio fibre. Your connection will be upgraded free. Install the app Jio Support from this link and give us the access code",
    "Final notice from Income Tax Department: you owe Rs 42,300 as pending tax. Pay immediately at http://itd-payments.click or your bank account will be seized",
    "KBC Head Office: Your number was selected for the 25 lakh jackpot. Contact manager Rana Pratap on 9777788888 and deposit tax Rs 12,000",
    "Dear student, you are eligible for the PM scholarship of Rs 50,000. Submit your Aadhaar, bank account and ATM PIN at http://pm-scholarship-apply.top",
    "This is a call from Mumbai Cyber Crime. Your Aadhaar was used in a money laundering case. Please stay on video call and do not disconnect until verification is complete",
    "Madam, Rs 15,000 has been wrongly sent to your account by me. Please return it immediately to this number 9000011111 else I will file a police complaint",
    "Hi, I am Anjali from HR at Amazon. Work from home, earn Rs 4,000 per day by rating products. Message me on Telegram to begin: t.me/amazon_hr_jobs",
    "Your Zerodha account has been flagged. Update your KYC by sharing the OTP you receive and PAN card photo on this chat or the account will be frozen",
    "You are under surveillance. A drug parcel in your name was intercepted by customs. Pay Rs 25,000 fine to settle or face arrest. Do not tell anyone.",
    "Great opportunity! Invest in our IPO pre-allotment scheme, assured 40% profit in 15 days. Send Rs 25,000 to UPI ipo.pre@oksbi",
    "आपका बिजली मीटर बदला जाएगा, इसके लिए अभी इस नंबर पर कॉल करें 9876500000 और 500 रुपये भेजें वरना कनेक्शन काट दिया जाएगा",
    "Dear customer, your Axis bank account is on hold due to PAN mismatch. Tap http://axis-pan-fix.xyz to resolve now",
    "Urgent help needed. I am in hospital and my card is blocked. Can you pay Rs 18,000 to my friend's account? I will return it tomorrow. Do not call, I can't talk",
    "Download the 'Free Fire diamonds' app from this link to get unlimited diamonds: http://ff-diamonds-free.top/ff.apk",
]

SAFE_V4 = [
    "HDFC Bank: Your EMI of Rs 12,450 for loan XX3321 is due on 5 Dec. Please keep sufficient balance in your account.",
    "Your traffic challan of Rs 500 for vehicle PB65 XX 1234 has been generated. Pay on the official Parivahan website within 60 days.",
    "Dear Candidate, you are selected for the Data Analyst role at Infosys. Please log in to the careers portal to view your offer letter and joining details.",
    "Bhai 500 rupaye PhonePe kar dena, kal chai ke paise lauta dunga.",
    "Your Amazon OTP is 713920. Don't share it with anyone, including Amazon delivery staff.",
    "SBI Alert: Your a/c XX4411 is credited with Rs 25,000 on 14-Nov by NEFT. Available bal Rs 61,332.",
    "Mom, I transferred Rs 5,000 to your account for the electricity bill. Please check.",
    "Your Star Health policy renewal premium Rs 14,200 is due on 30 Nov. Renew via the official app or website.",
    "Dear parent, school fee for term 2 is Rs 18,000. Last date 10 Dec. Pay by cheque or at the school accounts office.",
    "Hello, this is the delivery partner. I am outside your gate with your Zomato order. Please come down.",
    "Your Jio number 98XXXXXX45 has been recharged with Rs 749. Thank you.",
    "आपके खाते में 25,000 रुपये जमा हुए हैं। उपलब्ध शेष 61,332 रुपये। -पंजाब नेशनल बैंक",
    "Kal ka match dekhne aa jao, chips aur cold drink main laa dunga.",
    "ਬੈਂਕ ਵੱਲੋਂ ਸੂਚਨਾ: ਤੁਹਾਡੀ ਕਿਸ਼ਤ 8,500 ਰੁਪਏ 5 ਤਰੀਕ ਨੂੰ ਕੱਟੀ ਜਾਵੇਗੀ। ਕਿਰਪਾ ਕਰਕੇ ਖਾਤੇ ਵਿੱਚ ਪੈਸੇ ਰੱਖੋ।",
    "Reminder: your rent of Rs 15,000 is due on the 1st. Please transfer to the usual account.",
    "Dear customer, your debit card ending 4521 will expire next month. A new card will be sent to your registered address. No action is needed.",
    "Your electricity bill of Rs 2,310 for Nov has been generated. Pay online at the official PSPCL portal or the nearest centre by 20 Dec.",
    "Hi, this is Ravi from the society office. Maintenance of Rs 2,000 is due this month, you can pay at the office or by UPI to the society account.",
    "Court hearing for case 1234/2026 is listed on 12 Dec at 10:30 am in Room 4. Please carry your documents. -Advocate Mehta",
    "Your Kotak account statement for October is ready. Download it from the Kotak mobile app. Never share your OTP with anyone.",
    "Flipkart: Your refund of Rs 899 has been initiated and will reflect in 3-5 working days.",
    "Hi Anil, we would like to invite you for an interview on Monday 10 am at our Gurgaon office. Please bring your ID and certificates. No fees are charged at any stage.",
    "Your ticket is booked. Paid Rs 1,450 via UPI to IRCTC. PNR 8844221100.",
    "Papa ne bola hai ki shaam ko mandir chalna hai, 6 baje tak ready rehna.",
    "Dear member, your PF passbook is available on the UMANG app. For any query, call EPFO helpline 14470 (toll free).",
]


# ---------------------------------------------------------------------------
# Fifth corpus: final fresh hold-out (30 scams, 40 tricky genuine messages), measured once before tuning.
# ---------------------------------------------------------------------------
SCAMS_V5 = [
    "Dear Sir, Your Bank of Baroda account will be blocked within 24 hours if you do not update your PAN. Click: http://bob-pan-update.xyz",
    "Congratulations! You are the lucky winner of Rs 5,00,000 from Dream11. To receive your prize send Rs 2,000 as tax to 9876123450",
    "CBI notice: Your phone number is involved in illegal money transfer. You must cooperate in the investigation on WhatsApp video and not tell anyone, else arrest warrant will be issued",
    "Hi dear, I saw your profile. I want to invest in your business. Send your bank account number and OTP to receive the first payment",
    "Free Wi-Fi recharge for 1 year for BSNL customers, enter your mobile number, OTP and UPI PIN at http://bsnl-free-year.top",
    "Your DTH will be disconnected today. Recharge immediately by sending Rs 200 to 9810099100 on Google Pay",
    "Alert: someone is trying to withdraw Rs 74,000 from your account. To block, call the bank officer on 9654321078 and tell the OTP",
    "Looking for 10 people to do simple online tasks, daily payment 2500. Deposit Rs 800 as security first. WhatsApp 9812300045",
    "Your NEET/JEE result scholarship of Rs 1 lakh is pending. Pay Rs 1,500 for verification to release the amount",
    "Madam, I'm calling from SBI credit card department. Your card has been upgraded for free; to activate please tell me the 3 digit number on the back and the OTP",
    "Dear Customer your gas cylinder subsidy of Rs 800 is on hold. Update your KYC and bank details here: http://lpg-subsidy-kyc.top",
    "आपके आधार कार्ड से जुड़ा सिम अवैध गतिविधि में पाया गया है, गिरफ्तारी से बचने के लिए तुरंत पुलिस अधिकारी को 9876541230 पर कॉल करें",
    "बधाई हो! आपका नंबर 10 लाख रुपये के इनाम के लिए चुना गया है। इनाम पाने के लिए 3000 रुपये भेजें",
    "ਤੁਹਾਡੇ ਨਾਮ ਤੇ 5 ਲੱਖ ਦਾ ਲੋਨ ਮਨਜ਼ੂਰ ਹੋਇਆ ਹੈ, ਫਾਈਲ ਚਾਰਜ ਵਜੋਂ 3000 ਰੁਪਏ ਭੇਜੋ",
    "ਤੁਹਾਡੇ ਖਾਤੇ ਵਿੱਚ ਸ਼ੱਕੀ ਲੈਣ-ਦੇਣ ਹੋਇਆ ਹੈ, ਰੋਕਣ ਲਈ ਇਸ ਨੰਬਰ ਤੇ ਤੁਰੰਤ ਕਾਲ ਕਰੋ 9988001122",
    "Bhai urgent hai, mera account freeze ho gaya hai. Tu apne UPI se 15000 bhej de, kal subah wapas kar dunga, kisi ko mat batana",
    "Sir aapka parcel Delhi customs me ruka hai, clearance ke liye 6000 rupaye abhi bhejo warna parcel wapas ho jayega",
    "Aapka SIM aaj raat band ho jayega. KYC ke liye is number par turant call kare 9899012345",
    "Dear user, your Google Pay KYC expired. Account will be limited. Verify immediately: http://gpay-kyc-verify.click",
    "You have 1 pending court notice for cheque bounce. To avoid FIR pay Rs 4,500 today to this account and keep this confidential",
    "Join my crypto signals group, 90% accuracy, 20x returns. Pay Rs 3,000 membership. Telegram @cryptoking_signals",
    "Your Aadhaar has been used in a SIM fraud. Do not disconnect this call. A senior officer will verify your identity on video call",
    "Pay Rs 1 to verify your bank account and get Rs 500 cashback. Scan this QR and enter UPI PIN to complete",
    "Your electricity bill payment failed. Connection will be cut at 9.30 PM tonight. Call 9910101010 immediately to update",
    "Dear Customer, Rs 25,000 is credited to your account by mistake. Please send back Rs 25,000 to 9876543200 or legal action will be taken",
    "Kindly install the app 'SBI Rewards APK' from this link to claim your Rs 9,980 reward points: http://sbi-reward.apk-download.top/sbi.apk",
    "Hello, I'm calling from the Reserve Bank of India. Your account has been found with a counterfeit note. Transfer your balance to the RBI safe account to avoid arrest",
    "Dear Sir, income tax refund of Rs 9,340 is pending for your PAN. To get it, update bank account details and card number here: http://itr-refund-pan.top",
    "Make Rs 50,000 per month from home! No investment required. Registration fee Rs 999 only. Limited slots. Join WhatsApp group now",
    "Your WhatsApp number won the Coca-Cola online lottery 2026 of 85,000 pounds. Contact our agent with your name, age and pay Rs 4,500 clearing fee",
]

SAFE_V5 = [
    "Your OTP for Paytm login is 340912. Do not share with anyone. Paytm never calls to ask for OTP.",
    "Dear customer, Rs 5,000 has been debited from A/c XX9988 at POS on 18-Nov. If this was not done by you, call 1800-1111-09 (toll free) or visit your branch.",
    "Congratulations on clearing your exam! Mummy papa are so proud of you.",
    "Your cab has arrived. Driver Sunil, Swift Dzire PB08 CD 7788. OTP to start the ride is 4421.",
    "Hi, I have transferred Rs 2,000 to your account for the book. Please confirm once received.",
    "Thanks for shopping at Big Bazaar. You earned 120 reward points. Redeem them at the store.",
    "Your insurance claim of Rs 45,000 has been approved and will be credited to your registered account in 3 working days.",
    "Dear Sir, your income tax refund of Rs 9,340 has been processed and credited to your bank account ending 4411.",
    "Your Aadhaar update request has been received. Check status on the official UIDAI website with your URN.",
    "Hello, I'm calling from the bank regarding your loan application. Please visit the branch with your documents on Wednesday.",
    "Parcel update: Your Myntra order will be delivered today between 2 and 6 pm. Keep your phone reachable.",
    "Rent for November Rs 12,000 received. Thank you. -Mr Gupta",
    "Beta please send me the photo of the bill, I will pay it from the bank tomorrow.",
    "Meeting at 11 am tomorrow. Please send the report before that. Thanks.",
    "Your electricity bill for Nov Rs 1,640 is due on 20 Dec. Pay via the official app. Ignore if already paid.",
    "Job opening at Wipro Chandigarh for Associate Engineer. Apply at careers.wipro.com. No fee is charged for any stage of the hiring process.",
    "Your SIP of Rs 5,000 in Axis Bluechip Fund was processed on 5 Nov. Units allotted: 82.4.",
    "आपके खाते से 3,000 रुपये एटीएम से निकाले गए। अगर आपने नहीं निकाले तो बैंक की हेल्पलाइन 1800 पर कॉल करें।",
    "ਤੁਹਾਡਾ ਬਿਜਲੀ ਦਾ ਬਿੱਲ 1,450 ਰੁਪਏ ਹੈ, ਆਖਰੀ ਤਾਰੀਖ਼ 25 ਨਵੰਬਰ। ਭੁਗਤਾਨ ਅਧਿਕਾਰਤ ਐਪ ਰਾਹੀਂ ਕਰੋ।",
    "Bhai kal 5000 chahiye the, mil gaye? Main shaam ko UPI kar dunga.",
    "Tera courier aa gaya hai, gate pe guard ke paas rakha hai.",
    "Please note: your fixed deposit will mature on 30 Nov. Contact your branch for renewal options.",
    "Hello, this is a reminder from Dr Kapoor's clinic: your appointment is tomorrow at 4 pm. Fee Rs 500 payable at the clinic.",
    "Your WhatsApp backup is complete. 1.2 GB saved to Google Drive.",
    "Win exciting prizes at our store's Diwali lucky draw! Visit the Mall Road showroom this Sunday with your bill. Terms apply.",
    "Dear customer, your credit card statement for Nov is Rs 18,240. Minimum due Rs 912 by 12 Dec. Pay via netbanking or the app.",
    "OTP 556677 is your verification code for Swiggy. Valid for 10 minutes. Do not share.",
    "Your passport is ready for collection at the Regional Passport Office. Carry the appointment slip and ID.",
    "Hi Rohan, can you pay Rs 800 for the cab? I'll send you the details. UPI id is neha@okhdfc.",
    "School reopens on 3 Jan. Annual fee of Rs 22,000 can be paid at the accounts office or by cheque.",
    "Your Ola ride receipt: Rs 214 paid via UPI. Thank you for riding with us.",
    "Your Kisan Credit Card limit review is due. Please visit your nearest SBI branch with land records.",
    "Reminder from the gram panchayat: the pension disbursement camp is on 10 Dec at the panchayat bhawan. Carry your Aadhaar.",
    "Dear customer, never share your card PIN, CVV or OTP with anyone. Bank officials will never ask for them. -ICICI Bank",
    "Gas cylinder delivered. Please pay Rs 903 to the delivery person only after you receive the cylinder.",
    "Happy Gurpurab! Waheguru ji ka khalsa waheguru ji ki fateh 🙏",
    "Mausaji ka phone aaya tha, unhone kaha shaam ko ghar aayenge.",
    "Congratulations, your application for the scholarship has been shortlisted. Interview on 15 Dec at the college office. No fee is required.",
    "Final notice: library books are overdue. Please return them by Friday to avoid a fine of Rs 50.",
]


# ---------------------------------------------------------------------------
# Sixth corpus: last fresh hold-out (terse SMS-style, subtle and long-form scams + tricky genuine messages).
# ---------------------------------------------------------------------------
SCAMS_V6 = [
    "SBI: A/c blocked. Update KYC now http://sbi-kyc-secure.top",
    "Rs 50000 credited to ur acc by mistake pls return to 9812211223 urgent",
    "Hi mam, I'm Rohit from Flipkart. Your order is stuck. Share the 4 digit code sent to you to release it",
    "Hello, I found your lost wallet with Aadhaar. Send Rs 500 on Paytm for courier to get it back",
    "Paytm KYC expired. Account will close in 1 hr. Call 9871100110",
    "You've won 1 lakh in Tata Neu lucky spin. Claim now by paying Rs 49 processing: http://tata-neu-spin.top",
    "Hello ji, aap BSNL se ho na? Aapka tower ka rent 25000 mahina milega. Pehle 5000 registration fees bhejiye",
    "Congratulations you have been selected for 'Ladli Behna' scheme Rs 1500 monthly. Send Aadhaar and bank PIN to register",
    "Sir your Axis loan EMI bounced. Pay Rs 4,999 immediately on 9911223344 or legal case will be filed and relatives will be informed",
    "Namaste, main LIC se bol raha hu. Aapki policy lapse ho gayi hai, abhi 12000 online jama karein warna policy band ho jayegi aur paisa doob jayega",
    "Don't miss out! Double your money in 7 days with our forex robot. 1000 members already earned. DM @forexguru now",
    "Dear ma'am, your husband has been in an accident, please transfer Rs 30,000 to this number for hospital now",
    "Your Facebook page will be removed. Click to submit appeal: http://fb-appeal-center.click and enter password",
    "Mumbai Customs: A parcel addressed to you contains 5 passports and 200g contraband. Pay Rs 30,000 penalty today or arrest",
    "ਵਧਾਈਆਂ! ਤੁਸੀਂ 50 ਲੱਖ ਦੀ ਲਾਟਰੀ ਜਿੱਤੀ ਹੈ। ਇਨਾਮ ਲਈ 5000 ਰੁਪਏ ਪ੍ਰੋਸੈਸਿੰਗ ਫੀਸ ਭੇਜੋ",
    "ਤੁਹਾਡਾ ਸਿਮ ਕਾਰਡ ਅੱਜ ਬੰਦ ਹੋ ਜਾਵੇਗਾ। ਕੇਵਾਈਸੀ ਲਈ ਇਸ ਨੰਬਰ ਤੇ ਕਾਲ ਕਰੋ 9876511122",
    "आपका गैस कनेक्शन कट जाएगा। केवाईसी अपडेट के लिए तुरंत इस लिंक पर क्लिक करें http://gas-kyc-update.top",
    "आपके बेटे को पुलिस ने पकड़ लिया है। छुड़ाने के लिए अभी 50,000 रुपये भेजें और किसी को न बताएं",
    "Free Amazon voucher Rs 5000! Fill this form with your card number and CVV to receive: http://amzn-voucher.xyz",
    "Dear Customer, your ATM card is deactivated. To reactivate reply with card number, expiry and PIN",
    "Need a lady for babysitting, salary 30000/month. Send Rs 2000 for background verification to confirm",
    "Instagram influencer program: earn Rs 10,000 per post. Pay Rs 1,500 for the account verification badge",
    "Hello, this is the bank manager. We detected a hacker on your account. Move your funds to this safe account immediately to protect them",
    "TeamViewer id and password please, I will clear your pending electricity bill refund of Rs 3,200 from my system",
]

SAFE_V6 = [
    "SBI: Rs 500.00 debited from A/c XX1122 for UPI txn to Ramesh Kumar on 19-Nov. Not you? Call 1800 1122 55.",
    "Hello, your Flipkart order has been shipped and will arrive by Friday. Track in the app.",
    "Rohit bhai, 500 Paytm kar diya, check kar lo.",
    "Your Ola Money wallet has been credited with Rs 200 cashback. Thank you for riding.",
    "Dear customer, your Airtel number will be disconnected only if the bill remains unpaid beyond the due date. Pay by 28 Nov in the Airtel Thanks app.",
    "Bhai dukaan ka rent 15000 bhej dena, kal tak.",
    "Your appointment for Aadhaar biometric update is confirmed for Tuesday 11 am at the Seva Kendra. Carry original documents.",
    "ਕੱਲ੍ਹ ਸਵੇਰੇ ਗੁਰਦੁਆਰੇ ਵਿੱਚ ਪਾਠ ਹੈ, ਪਰਿਵਾਰ ਸਮੇਤ ਆਓ।",
    "आपका गैस सिलेंडर कल सुबह तक पहुंच जाएगा। कृपया डिलीवरी बॉय को ही भुगतान करें।",
    "Hi sir, I am calling from Axis Bank about your loan inquiry. When can you visit our branch with documents?",
    "Dear member, your LIC policy premium is due on 5 Dec. Pay at the nearest LIC office or the official LIC portal.",
    "Your TCS BPS interview is on 10 Dec at 10 am. Venue: Sector 62 Noida. Please carry your ID. This is a free process.",
    "Customs notice: your imported parcel requires duty of Rs 1,250. Pay only on the official ICEGATE portal.",
    "Winner of the college quiz: Aman Verma! Prize collection from the principal's office on Friday.",
    "Your credit card ending 8812 was used for Rs 1,999 at Amazon. If not you, block the card in the bank app or call the number on the back of your card.",
    "Paytm: Your money transfer of Rs 3,000 to Priya was successful.",
    "Papa ka message: beta apna khayal rakhna, aur time pe khana khana.",
    "Reminder: Gas booking amount Rs 903 will be collected on delivery. Do not pay in advance.",
    "Congratulations on your new job at Deloitte! Wishing you great success.",
    "आपका बीमा प्रीमियम 6,000 रुपये 10 दिसंबर को देय है। कृपया शाखा में जमा करें।",
    "Your electricity meter reading for Nov is 4821 units. Bill will be generated on 1 Dec.",
    "Final reminder: Your property tax Rs 6,800 for FY 2026-27 is due by 31 Dec. Pay at the municipal office or the official municipal portal.",
    "ਤੁਹਾਡੀ ਲੋਨ ਦੀ ਕਿਸ਼ਤ 4,200 ਰੁਪਏ 10 ਤਰੀਕ ਨੂੰ ਕੱਟੀ ਜਾਵੇਗੀ। ਕਿਰਪਾ ਕਰਕੇ ਖਾਤੇ ਵਿੱਚ ਬਕਾਇਆ ਰੱਖੋ।",
]


# Messages that are genuine in one situation and a scam in another (scammers use this exact wording). The app should
# warn rather than say "safe", but they are deliberately NOT counted in the accuracy numbers.
AMBIGUOUS = [
    "Hello, this is the Amazon delivery agent. I am at your door. Please share the delivery OTP only after you check the package.",
]
