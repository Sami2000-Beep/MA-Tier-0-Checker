from urllib.parse import urlparse


def normalize_url(raw_url: str) -> str:
    """Return a normalized URL with a scheme."""
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return ""
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url


def get_domain(url: str) -> str:
    """Extract hostname/domain from URL."""
    parsed = urlparse(normalize_url(url))
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host.split(":")[0]
