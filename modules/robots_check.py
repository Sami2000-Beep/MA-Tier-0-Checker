from typing import Dict, Any
import requests


def run_robots_check(base_url: str, timeout: int = 8) -> Dict[str, Any]:
    root = base_url.rstrip("/")
    robots_url = root + "/robots.txt"
    result = {"status": "Not checked", "url": robots_url, "notes": "", "sample": ""}
    try:
        r = requests.get(robots_url, timeout=timeout, headers={"User-Agent": "MA-Tier0-Assessment-Assistant/0.1"})
        if r.status_code == 200:
            text = r.text[:2000]
            result.update({
                "status": "Present",
                "sample": text[:500],
                "notes": "robots.txt present. Review disallow rules for tracking/scraping sensitivity."
            })
        else:
            result.update({"status": f"HTTP {r.status_code}", "notes": "robots.txt not found or not accessible."})
    except Exception as exc:
        result.update({"status": "Failed", "notes": f"robots.txt check failed: {exc}"})
    return result
