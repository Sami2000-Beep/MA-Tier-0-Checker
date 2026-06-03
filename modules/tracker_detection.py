import json
from pathlib import Path
from typing import Dict, Any, List


def load_trackers(path: str = "config/known_trackers.json") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def detect_trackers(html: str, tracker_config: dict | None = None) -> Dict[str, Any]:
    tracker_config = tracker_config or load_trackers()
    html_l = (html or "").lower()
    found: List[str] = []
    evidence = {}
    for name, patterns in tracker_config.items():
        hits = [p for p in patterns if p.lower() in html_l]
        if hits:
            found.append(name)
            evidence[name] = hits
    if found:
        notes = "Detected common tracking/analytics scripts: " + ", ".join(found)
    else:
        notes = "No configured common tracker patterns detected in fetched page source. This is not a full tracker audit."
    return {"found": found, "evidence": evidence, "notes": notes}
