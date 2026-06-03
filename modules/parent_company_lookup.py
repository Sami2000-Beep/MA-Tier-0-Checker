import re
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


USER_AGENT = "MA-Tier0-Assessment-Assistant/0.3"

CANDIDATE_PATHS = [
    "/",
    "/about",
    "/about-us",
    "/company",
    "/who-we-are",
    "/privacy",
    "/privacy-policy",
    "/terms",
    "/terms-of-service",
    "/legal",
    "/contact",
]


OWNERSHIP_PATTERNS = [
    r"owned by ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    r"operated by ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    r"provided by ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    r"a subsidiary of ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    r"part of ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    r"parent company(?: is)? ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    r"copyright ©?\s?\d{0,4}\s?([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    r"©\s?\d{0,4}\s?([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
]

LOCATION_PATTERNS = [
    r"headquartered in ([A-Z][A-Za-z.,'’\- ]{2,80})",
    r"headquarters (?:are|is) in ([A-Z][A-Za-z.,'’\- ]{2,80})",
    r"registered office (?:is )?(?:at|in) ([A-Z0-9][A-Za-z0-9.,#'’\- ]{2,120})",
    r"principal place of business (?:is )?(?:at|in) ([A-Z0-9][A-Za-z0-9.,#'’\- ]{2,120})",
    r"located in ([A-Z][A-Za-z.,'’\- ]{2,80})",
    r"based in ([A-Z][A-Za-z.,'’\- ]{2,80})",
]


COUNTRY_HINTS = {
    "United States": ["united states", "usa", "u.s.", "u.s.a.", "washington, dc", "new york", "california", "virginia"],
    "United Kingdom": ["united kingdom", "uk", "england", "london"],
    "Canada": ["canada", "ontario", "toronto", "ottawa"],
    "Australia": ["australia", "sydney", "melbourne", "canberra"],
    "New Zealand": ["new zealand", "wellington", "auckland"],
}


FVEY_COUNTRIES = {
    "United States",
    "United Kingdom",
    "Canada",
    "Australia",
    "New Zealand",
}


def _clean_text(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "")
    return text.strip()


def _clean_candidate(value: str) -> str:
    value = _clean_text(value)
    value = re.sub(r"\s*\|.*$", "", value)
    value = re.sub(r"\s*-.*$", "", value)
    value = value.strip(" .,:;|-/")
    return value[:120]


def _fetch_text(url: str, timeout: int = 10) -> Tuple[str, str]:
    """
    Returns visible text and final URL.
    """
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )

        if response.status_code >= 400:
            return "", url

        content_type = response.headers.get("content-type", "").lower()
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return "", response.url

        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup(["script", "style", "noscript", "svg"]):
            tag.decompose()

        visible_text = soup.get_text(" ", strip=True)

        # Add title/meta/footer-like signals when present
        title = soup.title.string if soup.title and soup.title.string else ""
        meta_desc = ""
        meta = soup.find("meta", attrs={"name": "description"})
        if meta and meta.get("content"):
            meta_desc = meta.get("content")

        combined = _clean_text(f"{title} {meta_desc} {visible_text}")
        return combined[:30000], response.url

    except Exception:
        return "", url


def _candidate_urls(base_url: str) -> List[str]:
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    urls = []
    for path in CANDIDATE_PATHS:
        urls.append(urljoin(root, path))

    # Preserve unique order
    seen = set()
    unique = []
    for u in urls:
        if u not in seen:
            unique.append(u)
            seen.add(u)

    return unique


def _find_pattern_hits(text: str, patterns: List[str]) -> List[str]:
    hits = []

    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            if match.groups():
                value = _clean_candidate(match.group(1))
                if value and len(value) >= 3:
                    hits.append(value)

    # Deduplicate while preserving order
    deduped = []
    seen = set()
    for hit in hits:
        key = hit.lower()
        if key not in seen:
            deduped.append(hit)
            seen.add(key)

    return deduped[:5]


def _infer_country(text: str, location_hits: List[str]) -> str:
    combined = f"{text} {' '.join(location_hits)}".lower()

    for country, hints in COUNTRY_HINTS.items():
        if any(hint in combined for hint in hints):
            return country

    return ""


def _infer_confidence(owner_hits: List[str], location_hits: List[str], country: str) -> str:
    if owner_hits and country:
        return "Medium"
    if owner_hits or location_hits or country:
        return "Low"
    return "Low"


def run_parent_company_lookup(url: str, domain: str = "") -> Dict[str, str]:
    """
    Attempts to identify parent company / ownership and location using
    homepage, About, Terms, Privacy, Legal, and Contact pages.

    This is an automated draft only and must be confirmed by an analyst.
    """
    result = {
        "status": "Manual Review Required",
        "possible_owner": "",
        "possible_location": "",
        "possible_country": "",
        "fvey_assessment": "Unknown",
        "confidence": "Low",
        "evidence_source": "",
        "notes": "",
    }

    if not url:
        result["notes"] = "No URL supplied for parent company lookup."
        return result

    all_owner_hits = []
    all_location_hits = []
    best_source = ""
    best_text_for_country = ""

    for candidate_url in _candidate_urls(url):
        text, final_url = _fetch_text(candidate_url)

        if not text:
            continue

        owner_hits = _find_pattern_hits(text, OWNERSHIP_PATTERNS)
        location_hits = _find_pattern_hits(text, LOCATION_PATTERNS)

        if owner_hits or location_hits:
            all_owner_hits.extend(owner_hits)
            all_location_hits.extend(location_hits)
            best_source = final_url
            best_text_for_country = text
            break

    # Deduplicate
    all_owner_hits = list(dict.fromkeys(all_owner_hits))
    all_location_hits = list(dict.fromkeys(all_location_hits))

    possible_owner = all_owner_hits[0] if all_owner_hits else ""
    possible_location = all_location_hits[0] if all_location_hits else ""
    possible_country = _infer_country(best_text_for_country, all_location_hits)

    if possible_country in FVEY_COUNTRIES:
        fvey_assessment = f"Possible FVEY jurisdiction: {possible_country}"
    elif possible_country:
        fvey_assessment = f"Possible non-FVEY jurisdiction: {possible_country}"
    else:
        fvey_assessment = "Unable to determine FVEY status automatically"

    confidence = _infer_confidence(all_owner_hits, all_location_hits, possible_country)

    if possible_owner or possible_location or possible_country:
        result.update(
            {
                "status": "Draft Found",
                "possible_owner": possible_owner,
                "possible_location": possible_location,
                "possible_country": possible_country,
                "fvey_assessment": fvey_assessment,
                "confidence": confidence,
                "evidence_source": best_source,
                "notes": (
                    "Automated parent company / ownership draft generated from public website text. "
                    "Analyst confirmation required using About, Terms, Privacy, Legal, Contact, "
                    "RDAP/WHOIS, and other approved sources."
                ),
            }
        )
    else:
        result.update(
            {
                "status": "Manual Review Required",
                "confidence": "Low",
                "fvey_assessment": "Unable to determine FVEY status automatically",
                "notes": (
                    "No parent company, legal entity, headquarters, or registered-office "
                    "signal was reliably identified from homepage/About/Terms/Privacy/Legal/Contact pages. "
                    "Manual review required."
                ),
            }
        )

    return result