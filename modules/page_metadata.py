from typing import Dict, Any
import requests
from bs4 import BeautifulSoup


def fetch_page_metadata(url: str, timeout: int = 10) -> Dict[str, Any]:
    result = {
        "status": "Not checked",
        "title": "",
        "description": "",
        "visible_text_sample": "",
        "html": "",
        "notes": ""
    }
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "MA-Tier0-Assessment-Assistant/0.1"}, allow_redirects=True)
        result["status"] = f"HTTP {r.status_code}"
        content_type = r.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            result["notes"] = f"Non-HTML content type: {content_type}"
            return result
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        desc_tag = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
        description = desc_tag.get("content", "").strip() if desc_tag else ""
        for tag in soup(["script", "style", "noscript"]):
            tag.extract()
        text = " ".join(soup.get_text(separator=" ").split())
        result.update({
            "title": title,
            "description": description,
            "visible_text_sample": text[:1000],
            "html": r.text[:500000],
            "notes": "Page metadata captured." if title or description else "Page loaded; limited metadata found."
        })
    except Exception as exc:
        result.update({"status": "Failed", "notes": f"Page metadata check failed: {exc}"})
    return result
