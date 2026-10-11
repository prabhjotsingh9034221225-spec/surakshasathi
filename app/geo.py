"""District lookup for the scam heatmap. Coordinates are approximate district centres."""
from __future__ import annotations

import unicodedata

# name -> (lat, lng, state)
DISTRICTS: dict[str, tuple[float, float, str]] = {
    # Punjab
    "Amritsar": (31.634, 74.872, "Punjab"), "Barnala": (30.378, 75.548, "Punjab"),
    "Bathinda": (30.211, 74.945, "Punjab"), "Faridkot": (30.672, 74.755, "Punjab"),
    "Fatehgarh Sahib": (30.644, 76.394, "Punjab"), "Fazilka": (30.403, 74.028, "Punjab"),
    "Ferozepur": (30.933, 74.613, "Punjab"), "Gurdaspur": (32.041, 75.405, "Punjab"),
    "Hoshiarpur": (31.532, 75.912, "Punjab"), "Jalandhar": (31.326, 75.576, "Punjab"),
    "Kapurthala": (31.380, 75.381, "Punjab"), "Ludhiana": (30.901, 75.857, "Punjab"),
    "Mansa": (29.988, 75.393, "Punjab"), "Moga": (30.816, 75.171, "Punjab"),
    "Mohali": (30.704, 76.717, "Punjab"), "Muktsar": (30.474, 74.516, "Punjab"),
    "Pathankot": (32.274, 75.652, "Punjab"), "Patiala": (30.339, 76.387, "Punjab"),
    "Rupnagar": (30.967, 76.533, "Punjab"), "Sangrur": (30.245, 75.842, "Punjab"),
    "Nawanshahr": (31.125, 76.116, "Punjab"), "Tarn Taran": (31.451, 74.928, "Punjab"),
    # Haryana
    "Ambala": (30.378, 76.776, "Haryana"), "Bhiwani": (28.793, 76.139, "Haryana"),
    "Charkhi Dadri": (28.592, 76.268, "Haryana"), "Faridabad": (28.408, 77.314, "Haryana"),
    "Fatehabad": (29.514, 75.455, "Haryana"), "Gurugram": (28.459, 77.027, "Haryana"),
    "Hisar": (29.154, 75.722, "Haryana"), "Jhajjar": (28.607, 76.657, "Haryana"),
    "Jind": (29.316, 76.315, "Haryana"), "Kaithal": (29.801, 76.399, "Haryana"),
    "Karnal": (29.686, 76.990, "Haryana"), "Kurukshetra": (29.969, 76.878, "Haryana"),
    "Mahendragarh": (28.274, 76.151, "Haryana"), "Nuh": (28.108, 77.001, "Haryana"),
    "Palwal": (28.144, 77.326, "Haryana"), "Panchkula": (30.695, 76.860, "Haryana"),
    "Panipat": (29.390, 76.968, "Haryana"), "Rewari": (28.198, 76.619, "Haryana"),
    "Rohtak": (28.895, 76.607, "Haryana"), "Sirsa": (29.534, 75.029, "Haryana"),
    "Sonipat": (28.995, 77.019, "Haryana"), "Yamunanagar": (30.130, 77.289, "Haryana"),
    # UT / metros
    "Chandigarh": (30.733, 76.779, "Chandigarh"), "Delhi": (28.614, 77.209, "Delhi"),
    "Jaipur": (26.912, 75.787, "Rajasthan"), "Lucknow": (26.847, 80.947, "Uttar Pradesh"),
    "Varanasi": (25.317, 82.973, "Uttar Pradesh"), "Patna": (25.594, 85.138, "Bihar"),
    "Bhopal": (23.259, 77.413, "Madhya Pradesh"), "Ahmedabad": (23.023, 72.572, "Gujarat"),
    "Mumbai": (19.076, 72.878, "Maharashtra"), "Pune": (18.520, 73.857, "Maharashtra"),
    "Hyderabad": (17.385, 78.487, "Telangana"), "Bengaluru": (12.972, 77.594, "Karnataka"),
    "Chennai": (13.083, 80.271, "Tamil Nadu"), "Kolkata": (22.573, 88.364, "West Bengal"),
}

ALIASES = {
    "gurgaon": "Gurugram", "gurugram": "Gurugram", "mohali": "Mohali", "sas nagar": "Mohali",
    "s.a.s. nagar": "Mohali", "ropar": "Rupnagar", "nawanshahr": "Nawanshahr", "sbs nagar": "Nawanshahr",
    "shaheed bhagat singh nagar": "Nawanshahr", "ferozpur": "Ferozepur", "firozpur": "Ferozepur",
    "new delhi": "Delhi", "bangalore": "Bengaluru", "bengaluru": "Bengaluru", "bombay": "Mumbai",
    "madras": "Chennai", "calcutta": "Kolkata", "tarntaran": "Tarn Taran", "sri muktsar sahib": "Muktsar",
    "fatehgarh": "Fatehgarh Sahib", "ambāla": "Ambala", "ਅੰਬਾਲਾ": "Ambala", "अंबाला": "Ambala",
    "ਲੁਧਿਆਣਾ": "Ludhiana", "लुधियाना": "Ludhiana", "ਅੰਮ੍ਰਿਤਸਰ": "Amritsar", "अमृतसर": "Amritsar",
    "ਜਲੰਧਰ": "Jalandhar", "जालंधर": "Jalandhar", "ਪਟਿਆਲਾ": "Patiala", "पटियाला": "Patiala",
    "ਬਠਿੰਡਾ": "Bathinda", "बठिंडा": "Bathinda", "ਚੰਡੀਗੜ੍ਹ": "Chandigarh", "चंडीगढ़": "Chandigarh",
    "दिल्ली": "Delhi", "ਦਿੱਲੀ": "Delhi", "रोहतक": "Rohtak", "हिसार": "Hisar", "करनाल": "Karnal",
    "गुरुग्राम": "Gurugram", "पानीपत": "Panipat", "सिरसा": "Sirsa", "कुरुक्षेत्र": "Kurukshetra",
}

_LOOKUP = {name.lower(): name for name in DISTRICTS}
_LOOKUP.update({k.lower(): v for k, v in ALIASES.items()})


def resolve_district(raw: str | None) -> str | None:
    if not raw:
        return None
    key = unicodedata.normalize("NFKC", raw).strip().lower().rstrip(".")
    key = " ".join(key.split())
    if key in _LOOKUP:
        return _LOOKUP[key]
    for alias, name in _LOOKUP.items():
        if len(alias) >= 4 and alias in key:
            return name
    return None


def coords(district: str) -> tuple[float, float] | None:
    info = DISTRICTS.get(district)
    return (info[0], info[1]) if info else None


def state_of(district: str) -> str | None:
    info = DISTRICTS.get(district)
    return info[2] if info else None
