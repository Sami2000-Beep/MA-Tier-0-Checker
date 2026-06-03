from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import requests

USER_AGENT = "MA-Tier0-Assessment-Assistant/0.2"
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Fallback endpoints for common TLDs. IANA bootstrap is tried first.
STATIC_RDAP_ENDPOINTS = {
    "com": ["https://rdap.verisign.com/com/v1/domain/"],
    "net": ["https://rdap.verisign.com/net/v1/domain/"],
    "org": ["https://rdap.publicinterestregistry.org/rdap/domain/"],
    "gov": ["https://rdap.dotgov.gov/domain/"],
    "edu": ["https://rdap.educause.edu/rdap/domain/"],
    "us": ["https://rdap.nic.us/domain/"],
    "info": ["https://rdap.afilias.net/rdap/info/domain/"],
    "biz": ["https://rdap.nic.biz/domain/"],
}


def _base_result() -> Dict[str, Any]:
    return {
        "status": "Not checked",
        "registrar": "",
        "country": "",
        "events": [],
        "nameservers": [],
        "source": "",
        "notes": "",
    }


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


def _extract_vcard_value(vcard_array: Any, fields: List[str]) -> str:
    """Extract common RDAP vCard values such as fn/org/country."""
    try:
        entries = vcard_array[1]
    except Exception:
        return ""
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        if entry[0] in fields and entry[3]:
            if isinstance(entry[3], list):
                return ", ".join(str(x) for x in entry[3] if x)
            return str(entry[3])
    return ""


def _extract_registrar(data: Dict[str, Any]) -> str:
    for ent in data.get("entities", []) or []:
        roles = [str(r).lower() for r in ent.get("roles", [])]
        if "registrar" in roles:
            registrar = _extract_vcard_value(ent.get("vcardArray"), ["org", "fn"])
            if registrar:
                return registrar
            handle = ent.get("handle")
            if handle:
                return str(handle)
    return ""


def _extract_country(data: Dict[str, Any]) -> str:
    if data.get("country"):
        return str(data.get("country"))
    for ent in data.get("entities", []) or []:
        # vCard adr value usually ends with country-name, but privacy redaction is common.
        country = _extract_vcard_value(ent.get("vcardArray"), ["adr"])
        if country:
            parts = [p.strip() for p in country.replace(";", ",").split(",") if p.strip()]
            if parts:
                return parts[-1]
    return ""


def _parse_rdap(data: Dict[str, Any], source: str) -> Dict[str, Any]:
    result = _base_result()
    nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if ns.get("ldhName")]
    events = [f"{e.get('eventAction','')}: {e.get('eventDate','')}" for e in data.get("events", [])]
    result.update({
        "status": "Found",
        "registrar": _extract_registrar(data),
        "country": _extract_country(data),
        "events": events[:6],
        "nameservers": nameservers[:6],
        "source": source,
        "notes": "RDAP lookup completed. Country may be blank/redacted; use registrar, nameservers, hosting, and analyst review for FVEY determination.",
    })
    return result


def _iana_endpoints_for(domain: str, timeout: int) -> List[str]:
    """Return RDAP endpoints from IANA bootstrap for the longest matching suffix."""
    try:
        r = requests.get(IANA_BOOTSTRAP_URL, timeout=timeout, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        data = r.json()
        labels = domain.split(".")
        suffixes = [".".join(labels[i:]) for i in range(len(labels))]
        for services in data.get("services", []):
            tlds, endpoints = services[0], services[1]
            if any(suffix in tlds for suffix in suffixes):
                return endpoints or []
    except Exception:
        return []
    return []


def _candidate_endpoints(domain: str, timeout: int) -> List[str]:
    endpoints: List[str] = []
    endpoints.extend(_iana_endpoints_for(domain, timeout))
    tld = domain.split(".")[-1]
    endpoints.extend(STATIC_RDAP_ENDPOINTS.get(tld, []))
    endpoints.append("https://rdap.org/domain/")

    # Preserve order and de-duplicate.
    unique: List[str] = []
    for endpoint in endpoints:
        if endpoint and endpoint not in unique:
            unique.append(endpoint)
    return unique


def _build_url(endpoint: str, domain: str) -> str:
    endpoint = endpoint.strip()
    if endpoint.endswith("/"):
        return endpoint + domain
    return endpoint + "/" + domain


def run_rdap_lookup(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """Query RDAP for a domain using IANA bootstrap, static fallbacks, then rdap.org."""
    result = _base_result()
    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        result.update({"status": "Manual Review Required", "notes": "Invalid or incomplete domain supplied for RDAP lookup."})
        return result

    errors: List[str] = []
    for endpoint in _candidate_endpoints(domain, timeout):
        url = _build_url(endpoint, domain)
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"})
            if r.status_code == 200:
                return _parse_rdap(r.json(), url)
            if r.status_code in (404, 501):
                errors.append(f"{endpoint} returned HTTP {r.status_code}")
                continue
            errors.append(f"{endpoint} returned HTTP {r.status_code}")
        except Exception as exc:
            errors.append(f"{endpoint} error: {exc}")

    result.update({
        "status": "Manual Review Required",
        "notes": "RDAP lookup could not be completed automatically. This is usually caused by network/DNS blocking, an unsupported TLD, or the registry not publishing useful RDAP data. Try manual WHOIS/CentralOps/Domain Dossier review. Details: " + " | ".join(errors[:3]),
    })
    return result
