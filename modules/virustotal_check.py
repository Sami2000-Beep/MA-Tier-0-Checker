import base64
import os
import time
from typing import Dict, Any

import requests


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def get_api_key() -> str:
    return os.getenv("VT_API_KEY", "").strip()


def run_virustotal_url_check(url: str, api_key: str | None = None, submit_if_missing: bool = True) -> Dict[str, Any]:
    """Check a URL using VirusTotal API v3.

    Attempts to retrieve the existing URL report first. If missing and submit_if_missing=True,
    submits the URL for analysis and then tries to retrieve the report after a short wait.
    """
    api_key = (api_key or get_api_key()).strip()
    result = {
        "status": "Not checked",
        "malicious": None,
        "suspicious": None,
        "harmless": None,
        "undetected": None,
        "timeout": None,
        "notes": "",
        "permalink": f"https://www.virustotal.com/gui/url/{_url_id(url)}"
    }
    if not api_key:
        result.update({"status": "No API key", "notes": "VirusTotal API key not configured. Manual review required."})
        return result

    headers = {"x-apikey": api_key, "accept": "application/json"}
    try:
        report_url = f"https://www.virustotal.com/api/v3/urls/{_url_id(url)}"
        r = requests.get(report_url, headers=headers, timeout=15)
        if r.status_code == 404 and submit_if_missing:
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15,
            )
            if submit.status_code not in (200, 201):
                result.update({"status": f"Submit failed HTTP {submit.status_code}", "notes": submit.text[:500]})
                return result
            time.sleep(8)
            r = requests.get(report_url, headers=headers, timeout=15)

        if r.status_code != 200:
            result.update({"status": f"HTTP {r.status_code}", "notes": r.text[:500]})
            return result

        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        result.update({
            "status": "Report found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "notes": (
                f"VirusTotal: {stats.get('malicious', 0)} malicious / "
                f"{stats.get('suspicious', 0)} suspicious / "
                f"{stats.get('harmless', 0)} harmless / "
                f"{stats.get('undetected', 0)} undetected."
            )
        })
    except Exception as exc:
        result.update({"status": "Failed", "notes": f"VirusTotal check failed: {exc}"})
    return result
