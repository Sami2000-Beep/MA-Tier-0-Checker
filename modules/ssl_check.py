import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any


def run_ssl_check(domain: str, timeout: int = 8) -> Dict[str, Any]:
    result = {
        "status": "Not checked",
        "valid": False,
        "issuer": "",
        "subject": "",
        "not_after": "",
        "notes": ""
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter", "")
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        is_valid = expires > datetime.now(timezone.utc)
        issuer = ", ".join("=".join(x) for part in cert.get("issuer", []) for x in part)
        subject = ", ".join("=".join(x) for part in cert.get("subject", []) for x in part)
        result.update({
            "status": "Valid" if is_valid else "Expired",
            "valid": is_valid,
            "issuer": issuer,
            "subject": subject,
            "not_after": expires.strftime("%Y-%m-%d"),
            "notes": f"SSL certificate {'valid' if is_valid else 'expired'}; expires {expires.strftime('%Y-%m-%d')}"
        })
    except Exception as exc:
        result.update({"status": "Failed", "notes": f"SSL check failed: {exc}"})
    return result
