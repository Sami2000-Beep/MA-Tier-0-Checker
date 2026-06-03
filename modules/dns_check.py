import socket
from typing import Dict, Any


def run_dns_check(domain: str) -> Dict[str, Any]:
    result = {"status": "Not checked", "ip_addresses": [], "notes": ""}
    try:
        records = socket.getaddrinfo(domain, None)
        ips = sorted({item[4][0] for item in records})
        result.update({
            "status": "Resolved" if ips else "No records found",
            "ip_addresses": ips,
            "notes": f"Resolved to {', '.join(ips[:5])}" if ips else "No IP addresses found."
        })
    except Exception as exc:
        result.update({"status": "Failed", "notes": f"DNS resolution failed: {exc}"})
    return result
