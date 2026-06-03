import json
from pathlib import Path
from typing import Dict, Any


FALLBACK_FVEY_TERMS = {
    "us",
    "usa",
    "united states",
    "united states of america",
    "canada",
    "ca",
    "united kingdom",
    "uk",
    "gb",
    "australia",
    "au",
    "new zealand",
    "nz",
}

UNKNOWN_COUNTRY_TERMS = {
    "",
    "redacted for privacy",
    "privacy redacted",
    "redacted",
    "unknown",
    "not disclosed",
    "n/a",
}


def _load_fvey_terms() -> set[str]:
    config_path = Path(__file__).resolve().parents[1] / "config" / "fvey_countries.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            str(value).strip().lower()
            for value in data.get("FVEY", [])
            if str(value).strip()
        }
    except Exception:
        return FALLBACK_FVEY_TERMS


FVEY_TERMS = _load_fvey_terms()


def suggest_recommendation(assessment: Dict[str, Any]) -> Dict[str, str]:
    """Conservative SOP-aligned recommendation."""
    reasons = []
    vt = assessment.get("virustotal", {})
    ssl = assessment.get("ssl", {})
    rdap = assessment.get("rdap", {})

    malicious = vt.get("malicious")
    suspicious = vt.get("suspicious")
    if malicious is not None:
        if malicious >= 2 or (malicious >= 1 and (suspicious or 0) >= 1):
            reasons.append("VirusTotal shows multiple malicious/suspicious indicators.")
            return {"recommendation": "Unsuitable", "reason": "; ".join(reasons)}
        if malicious == 1 or (suspicious or 0) >= 1:
            reasons.append("VirusTotal has a limited malicious/suspicious signal requiring analyst review.")
            return {"recommendation": "Needs Review", "reason": "; ".join(reasons)}
    else:
        reasons.append("VirusTotal result incomplete or unavailable.")

    if ssl.get("status") in ("Expired", "Failed"):
        reasons.append("SSL certificate check failed or certificate expired.")
        return {"recommendation": "Needs Review", "reason": "; ".join(reasons)}

    country = str(rdap.get("country", "")).strip().lower()
    if country and country not in UNKNOWN_COUNTRY_TERMS and country not in FVEY_TERMS:
        reasons.append(f"RDAP country appears non-FVEY or unclear: {rdap.get('country')}")
        return {"recommendation": "Exception–Escalate", "reason": "; ".join(reasons)}

    if country in UNKNOWN_COUNTRY_TERMS:
        reasons.append("RDAP country is redacted or unavailable; analyst origin review is still required.")

    if (
        vt.get("malicious") == 0
        and vt.get("suspicious") == 0
        and ssl.get("valid") is True
        and not reasons
    ):
        reasons.append("No VT malicious/suspicious findings and SSL appears valid. Analyst must still complete topical/reputation review.")
        return {"recommendation": "Suitable", "reason": "; ".join(reasons)}

    reasons.append("Insufficient automated evidence for final determination.")
    return {"recommendation": "Needs Review", "reason": "; ".join(reasons)}
