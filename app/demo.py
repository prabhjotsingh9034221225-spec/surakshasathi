"""Demo helpers: realistic sample scam data so the heatmap is not empty on stage.

Seeded rows are tagged channel='seed' and the dashboard labels them as sample data.
"""
from __future__ import annotations

import random
import time

from . import storage
from .geo import DISTRICTS

# (category, snippet, weight)
SAMPLES = [
    ("kyc", "Your SBI account is blocked. Update KYC now [link]", 30),
    ("otp", "Share the OTP sent to your phone to avoid account closure", 18),
    ("upi_collect", "Approve the collect request to receive your refund", 16),
    ("lottery", "You won Rs 25 lakh in KBC lottery. Pay processing fee", 10),
    ("electricity", "Electricity will be disconnected tonight 9:30pm. Call now", 10),
    ("legal_threat", "CBI notice: you are under digital arrest, stay on the video call", 6),
    ("remote_access", "Install AnyDesk so we can process your refund", 5),
    ("job_scam", "Earn Rs 5000 daily from home, like and subscribe tasks", 5),
]

# Rough weighting: northern districts are the focus of the demo.
HOT = {"Ludhiana": 9, "Amritsar": 7, "Jalandhar": 7, "Ambala": 6, "Patiala": 6, "Mohali": 6, "Gurugram": 8,
       "Hisar": 5, "Karnal": 4, "Bathinda": 4, "Delhi": 9, "Chandigarh": 5, "Faridabad": 5, "Rohtak": 4,
       "Panipat": 3, "Sirsa": 3, "Moga": 3, "Sangrur": 3, "Yamunanagar": 2, "Kurukshetra": 2}


def seed_reports(n: int = 150, seed: int = 7) -> int:
    rng = random.Random(seed)
    districts = [d for d in HOT if d in DISTRICTS]
    d_weights = [HOT[d] for d in districts]
    cats = [(c, s) for c, s, _ in SAMPLES]
    c_weights = [w for _, _, w in SAMPLES]
    now = time.time()
    for _ in range(n):
        district = rng.choices(districts, d_weights)[0]
        cat, snippet = rng.choices(cats, c_weights)[0]
        storage.add_report(
            district=district,
            verdict="scam" if rng.random() < 0.85 else "suspicious",
            score=rng.randint(62, 100),
            category=cat,
            snippet=snippet,
            channel="seed",
            ts=now - rng.uniform(0, 14 * 86400),
        )
    return n
