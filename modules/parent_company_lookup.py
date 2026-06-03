import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

try:
    from ddgs import DDGS
except Exception:
    DDGS = None


USER_AGENT = "MA-Tier0-Assessment-Assistant/0.5"

WIKIDATA_SPARQL_URL = "https://query.wikidata.org/sparql"
WIKIDATA_ENTITY_URL = "https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"

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


KNOWN_OWNER_OVERRIDES = {
    "cnn.com": {
        "owner": "Warner Bros. Discovery",
        "location": "New York, United States",
        "confidence": "High",
        "source": "Known mapping",
    },
    "bbc.com": {
        "owner": "British Broadcasting Corporation",
        "location": "London, United Kingdom",
        "confidence": "High",
        "source": "Known mapping",
    },
    "wikipedia.org": {
        "owner": "Wikimedia Foundation",
        "location": "San Francisco, United States",
        "confidence": "High",
        "source": "Known mapping",
    },
    "loc.gov": {
        "owner": "Library of Congress",
        "location": "Washington, DC, United States",
        "confidence": "High",
        "source": "Known mapping",
    },
    "army.mil": {
        "owner": "United States Army",
        "location": "Washington, DC, United States",
        "confidence": "High",
        "source": "Known mapping",
    },
}


COUNTRY_HINTS = {
    "United States": [
        "united states",
        "usa",
        "u.s.",
        "u.s.a.",
        "washington, dc",
        "washington d.c.",
        "new york",
        "california",
        "virginia",
        "georgia",
        "texas",
        "illinois",
        "massachusetts",
        "san francisco",
        "atlanta",
    ],
    "United Kingdom": [
        "united kingdom",
        "uk",
        "england",
        "london",
        "scotland",
        "wales",
    ],
    "Canada": [
        "canada",
        "toronto",
        "ottawa",
        "ontario",
        "montreal",
        "vancouver",
    ],
    "Australia": [
        "australia",
        "sydney",
        "melbourne",
        "canberra",
    ],
    "New Zealand": [
        "new zealand",
        "wellington",
        "auckland",
    ],
}


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _clean_domain(value: str) -> str:
    value = (value or "").strip().lower()

    if not value:
        return ""

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path

    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split(":")[0]

    if value.startswith("www."):
        value = value[4:]

    return value.strip(".")


def _root_url(url: str) -> str:
    parsed = urlparse(url)

    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    return f"{parsed.scheme}://{parsed.netloc}"


def _infer_country(text: str) -> str:
    lower = (text or "").lower()

    for country, hints in COUNTRY_HINTS.items():
        if any(hint in lower for hint in hints):
            return country

    return ""


def _result(
    owner: str = "",
    location: str = "",
    confidence: str = "Low",
    status: str = "Manual Review Required",
    source: str = "",
    notes: str = "",
) -> Dict[str, str]:
    return {
        "status": status,
        "possible_owner": owner or "Unable to determine",
        "possible_location": location or "Unable to determine",
        "possible_country": _infer_country(location) if location else "",
        "confidence": confidence or "Low",
        "evidence_source": source,
        "notes": notes,
    }


def _wikidata_sparql(query: str, timeout: int = 15) -> List[Dict[str, Any]]:
    try:
        response = requests.get(
            WIKIDATA_SPARQL_URL,
            params={"query": query, "format": "json"},
            headers={
                "Accept": "application/sparql-results+json",
                "User-Agent": USER_AGENT,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("results", {}).get("bindings", [])
    except Exception:
        return []


def _wikidata_find_entity_by_domain(domain: str) -> Optional[Dict[str, str]]:
    """
    Finds a Wikidata entity whose official website contains the target domain.
    Uses P856 official website.
    """
    domain = _clean_domain(domain)
    if not domain:
        return None

    query = f"""
    SELECT ?item ?itemLabel ?website WHERE {{
      ?item wdt:P856 ?website .
      FILTER(CONTAINS(LCASE(STR(?website)), "{domain}"))
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }}
    LIMIT 5
    """

    bindings = _wikidata_sparql(query)

    for b in bindings:
        item_uri = b.get("item", {}).get("value", "")
        label = b.get("itemLabel", {}).get("value", "")
        website = b.get("website", {}).get("value", "")

        if not item_uri or not label:
            continue

        qid = item_uri.rstrip("/").split("/")[-1]

        return {
            "qid": qid,
            "label": label,
            "website": website,
        }

    return None


def _wikidata_get_entity_relationships(qid: str) -> Dict[str, str]:
    """
    Gets parent organization / owned by / headquarters / country for a Wikidata entity.
    Properties:
      P749 = parent organization
      P127 = owned by
      P159 = headquarters location
      P17 = country
    """
    query = f"""
    SELECT
      ?entity ?entityLabel
      ?parent ?parentLabel
      ?ownedBy ?ownedByLabel
      ?hq ?hqLabel
      ?country ?countryLabel
      ?parentHq ?parentHqLabel
      ?parentCountry ?parentCountryLabel
      ?ownedByHq ?ownedByHqLabel
      ?ownedByCountry ?ownedByCountryLabel
    WHERE {{
      BIND(wd:{qid} AS ?entity)

      OPTIONAL {{ ?entity wdt:P749 ?parent. }}
      OPTIONAL {{ ?entity wdt:P127 ?ownedBy. }}
      OPTIONAL {{ ?entity wdt:P159 ?hq. }}
      OPTIONAL {{ ?entity wdt:P17 ?country. }}

      OPTIONAL {{ ?parent wdt:P159 ?parentHq. }}
      OPTIONAL {{ ?parent wdt:P17 ?parentCountry. }}

      OPTIONAL {{ ?ownedBy wdt:P159 ?ownedByHq. }}
      OPTIONAL {{ ?ownedBy wdt:P17 ?ownedByCountry. }}

      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }}
    LIMIT 10
    """

    bindings = _wikidata_sparql(query)

    if not bindings:
        return {}

    best = bindings[0]

    def val(key: str) -> str:
        return best.get(key, {}).get("value", "")

    entity_label = val("entityLabel")
    parent_label = val("parentLabel")
    owned_by_label = val("ownedByLabel")
    hq_label = val("hqLabel")
    country_label = val("countryLabel")
    parent_hq_label = val("parentHqLabel")
    parent_country_label = val("parentCountryLabel")
    owned_by_hq_label = val("ownedByHqLabel")
    owned_by_country_label = val("ownedByCountryLabel")

    # Owner priority:
    # 1. Parent organization
    # 2. Owned by
    # 3. Entity itself
    owner = parent_label or owned_by_label or entity_label

    # Location priority:
    # If owner is parent, use parent HQ/country.
    # If owner is owned-by, use owned-by HQ/country.
    # Otherwise use entity HQ/country.
    if parent_label:
        location_parts = [parent_hq_label, parent_country_label]
    elif owned_by_label:
        location_parts = [owned_by_hq_label, owned_by_country_label]
    else:
        location_parts = [hq_label, country_label]

    location_parts = [p for p in location_parts if p]
    location = ", ".join(dict.fromkeys(location_parts))

    return {
        "entity": entity_label,
        "owner": owner,
        "location": location,
        "parent": parent_label,
        "owned_by": owned_by_label,
        "hq": hq_label,
        "country": country_label,
    }


def _wikidata_lookup(domain: str) -> Dict[str, str]:
    entity = _wikidata_find_entity_by_domain(domain)

    if not entity:
        return _result(
            confidence="Low",
            status="Manual Review Required",
            source="Wikidata",
            notes="No Wikidata entity found by official website/domain.",
        )

    relationships = _wikidata_get_entity_relationships(entity["qid"])

    owner = relationships.get("owner", "")
    location = relationships.get("location", "")

    if owner and location:
        return _result(
            owner=owner,
            location=location,
            confidence="High",
            status="Draft Found",
            source=f"Wikidata {entity['qid']}",
            notes="Wikidata official website and ownership/location properties found.",
        )

    if owner:
        return _result(
            owner=owner,
            location="Unable to determine",
            confidence="Medium",
            status="Draft Found",
            source=f"Wikidata {entity['qid']}",
            notes="Wikidata owner found but location was not available.",
        )

    return _result(
        owner=entity.get("label", ""),
        location="Unable to determine",
        confidence="Low",
        status="Draft Found",
        source=f"Wikidata {entity['qid']}",
        notes="Wikidata entity found, but parent/owned-by/location properties were incomplete.",
    )


def _ddgs_search(query: str, max_results: int = 5) -> List[Dict[str, str]]:
    if DDGS is None:
        return []

    try:
        results = []
        with DDGS() as ddgs:
            for item in ddgs.text(query, max_results=max_results):
                results.append(
                    {
                        "title": item.get("title", "") or "",
                        "href": item.get("href", "") or "",
                        "body": item.get("body", "") or "",
                    }
                )
        return results
    except Exception:
        return []


def _clean_owner(owner: str) -> str:
    owner = _clean_text(owner)
    owner = re.sub(r"\s*[|–—-].*$", "", owner)
    owner = re.sub(r"\s*\(.*?\).*$", "", owner)
    owner = owner.strip(" .,:;")

    if owner.lower() in {"the", "a", "an", "it", "its", "this", "that", "website", "company", "parent"}:
        return ""

    return owner[:100]


def _clean_location(location: str) -> str:
    location = _clean_text(location)
    location = re.sub(r"\s*[|–—-].*$", "", location)
    location = location.strip(" .,:;")
    return location[:120]


def _extract_owner_from_search(results: List[Dict[str, str]]) -> str:
    combined = " ".join(
        _clean_text(f"{item.get('title', '')} {item.get('body', '')}")
        for item in results
    )

    patterns = [
        r"parent company (?:is|of)?\s*[:\-]?\s*([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"owned by\s+([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"owner\s*[:\-]\s*([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"operated by\s+([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"subsidiary of\s+([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"part of\s+([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    ]

    for pattern in patterns:
        match = re.search(pattern, combined, flags=re.IGNORECASE)
        if match:
            owner = _clean_owner(match.group(1))
            if owner:
                return owner

    return ""


def _extract_location_from_search(results: List[Dict[str, str]]) -> str:
    combined = " ".join(
        _clean_text(f"{item.get('title', '')} {item.get('body', '')}")
        for item in results
    )

    patterns = [
        r"headquartered in\s+([A-Z][A-Za-z.,'’\- ]{2,100})",
        r"headquarters (?:is|are)\s+(?:in|at)\s+([A-Z][A-Za-z.,'’\- ]{2,100})",
        r"based in\s+([A-Z][A-Za-z.,'’\- ]{2,100})",
        r"located in\s+([A-Z][A-Za-z.,'’\- ]{2,100})",
        r"registered office (?:is )?(?:in|at)\s+([A-Z0-9][A-Za-z0-9.,#'’\- ]{2,120})",
    ]

    for pattern in patterns:
        match = re.search(pattern, combined, flags=re.IGNORECASE)
        if match:
            location = _clean_location(match.group(1))
            if location:
                return location

    country = _infer_country(combined)
    if country:
        return country

    return ""


def _search_fallback(domain: str) -> Dict[str, str]:
    owner = ""

    owner_queries = [
        f"parent company of {domain}",
        f"who owns {domain}",
        f"{domain} owner parent company",
        f"{domain} owned by company",
    ]

    for query in owner_queries:
        owner = _extract_owner_from_search(_ddgs_search(query, max_results=5))
        if owner:
            break

    location = ""

    if owner:
        location_queries = [
            f"{owner} headquarters location",
            f"where is {owner} headquartered",
            f"{owner} corporate headquarters",
            f"{owner} location country",
        ]

        for query in location_queries:
            location = _extract_location_from_search(_ddgs_search(query, max_results=5))
            if location:
                break

    if owner and location:
        return _result(
            owner=owner,
            location=location,
            confidence="Medium",
            status="Draft Found",
            source="DDGS search fallback",
            notes="Search fallback found owner and location. Analyst confirmation required.",
        )

    if owner:
        return _result(
            owner=owner,
            location="Unable to determine",
            confidence="Low",
            status="Draft Found",
            source="DDGS search fallback",
            notes="Search fallback found owner but not location. Analyst confirmation required.",
        )

    return _result(
        confidence="Low",
        status="Manual Review Required",
        source="DDGS search fallback",
        notes="Search fallback did not identify a reliable owner/location.",
    )


def _candidate_urls(base_url: str) -> List[str]:
    root = _root_url(base_url)

    urls = []
    for path in CANDIDATE_PATHS:
        urls.append(urljoin(root, path))

    seen = set()
    unique = []

    for u in urls:
        if u not in seen:
            unique.append(u)
            seen.add(u)

    return unique


def _fetch_text(url: str, timeout: int = 10) -> Tuple[str, str]:
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

        title = soup.title.string if soup.title and soup.title.string else ""

        meta_desc = ""
        meta = soup.find("meta", attrs={"name": "description"})
        if meta and meta.get("content"):
            meta_desc = meta.get("content")

        visible_text = soup.get_text(" ", strip=True)
        combined = _clean_text(f"{title} {meta_desc} {visible_text}")
        return combined[:30000], response.url

    except Exception:
        return "", url


def _site_scan_fallback(url: str) -> Dict[str, str]:
    owner_patterns = [
        r"owned by ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"operated by ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"provided by ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"a subsidiary of ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"part of ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"parent company(?: is)? ([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"copyright ©?\s?\d{0,4}\s?([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
        r"©\s?\d{0,4}\s?([A-Z][A-Za-z0-9&.,'’\- ]{2,80})",
    ]

    location_patterns = [
        r"headquartered in ([A-Z][A-Za-z.,'’\- ]{2,80})",
        r"headquarters (?:are|is) in ([A-Z][A-Za-z.,'’\- ]{2,80})",
        r"registered office (?:is )?(?:at|in) ([A-Z0-9][A-Za-z0-9.,#'’\- ]{2,120})",
        r"principal place of business (?:is )?(?:at|in) ([A-Z0-9][A-Za-z0-9.,#'’\- ]{2,120})",
        r"located in ([A-Z][A-Za-z.,'’\- ]{2,80})",
        r"based in ([A-Z][A-Za-z.,'’\- ]{2,80})",
    ]

    owner = ""
    location = ""

    for candidate_url in _candidate_urls(url):
        text, final_url = _fetch_text(candidate_url)

        if not text:
            continue

        for pattern in owner_patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                owner = _clean_owner(match.group(1))
                break

        for pattern in location_patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                location = _clean_location(match.group(1))
                break

        if owner or location:
            confidence = "Low"
            if owner and location:
                confidence = "Medium"

            return _result(
                owner=owner,
                location=location,
                confidence=confidence,
                status="Draft Found",
                source=final_url,
                notes="Website legal/about page fallback found ownership/location signal.",
            )

    return _result(
        confidence="Low",
        status="Manual Review Required",
        source="Website fallback scan",
        notes="Website fallback scan did not identify a reliable owner/location.",
    )


def run_parent_company_lookup(url: str, domain: str = "") -> Dict[str, str]:
    """
    Wikidata-first ownership/location lookup.

    Priority:
      1. Known overrides for common high-confidence domains
      2. Wikidata official website lookup
      3. DDGS search fallback
      4. Website legal/about/privacy/terms scan fallback

    Output supports clean Origin field:
      Possible Owner
      Possible Location
      Confidence
    """
    clean_domain = _clean_domain(domain or url)

    if not clean_domain:
        return _result(
            confidence="Low",
            status="Manual Review Required",
            source="Input validation",
            notes="No usable domain supplied.",
        )

    if clean_domain in KNOWN_OWNER_OVERRIDES:
        known = KNOWN_OWNER_OVERRIDES[clean_domain]
        return _result(
            owner=known["owner"],
            location=known["location"],
            confidence=known["confidence"],
            status="Draft Found",
            source=known["source"],
            notes="Known high-confidence public ownership mapping. Analyst confirmation still recommended.",
        )

    wikidata_result = _wikidata_lookup(clean_domain)
    if wikidata_result.get("possible_owner") != "Unable to determine":
        return wikidata_result

    search_result = _search_fallback(clean_domain)
    if search_result.get("possible_owner") != "Unable to determine":
        return search_result

    return _site_scan_fallback(url)