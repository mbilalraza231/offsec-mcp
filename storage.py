"""
storage.py — save and list recon results on disk.

Files land in ./output/<domain>_<timestamp>.json
"""

import json
import re
from datetime import datetime
from pathlib import Path

from config import OUTPUT_DIR

SAFE = re.compile(r"[^a-zA-Z0-9._-]")


def save_results(domain: str, results: dict) -> dict:
    OUTPUT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = SAFE.sub("_", domain.strip().lower()) or "unknown"
    path = OUTPUT_DIR / f"{safe_domain}_{stamp}.json"
    payload = {
        "domain": domain,
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return {"saved_to": str(path), "size_bytes": path.stat().st_size}


def list_scans() -> dict:
    if not OUTPUT_DIR.exists():
        return {"scans": []}
    scans = []
    for f in sorted(OUTPUT_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            scans.append({
                "file": f.name,
                "domain": data.get("domain"),
                "saved_at": data.get("saved_at"),
            })
        except Exception:
            continue
    return {"count": len(scans), "scans": scans}
