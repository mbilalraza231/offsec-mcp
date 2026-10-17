"""
tools/vuln.py — vulnerability scan with nuclei.

No pure-Python fallback — nuclei's template engine is irreplaceable.
If nuclei is missing, returns a clear message telling the user to install it.
"""

import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from config import find_tool

TIMEOUT = 300  # 5 min cap


def scan_vulnerabilities(targets: list[str]) -> dict:
    if not targets:
        return {"findings": [], "count": 0, "severity_breakdown": {}}

    nuclei = find_tool("nuclei")
    if not nuclei:
        return {
            "findings": [],
            "count": 0,
            "severity_breakdown": {},
            "message": (
                "nuclei not installed — run installers/install-tools.ps1 "
                "or download from https://github.com/projectdiscovery/nuclei/releases"
            ),
        }

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        target_file = f.name

    try:
        proc = subprocess.run(
            [nuclei, "-l", target_file, "-silent", "-json", "-no-color",
             "-severity", "info,low,medium,high,critical"],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        findings = []
        for line in proc.stdout.splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "template": obj.get("info", {}).get("name"),
                    "severity": obj.get("info", {}).get("severity"),
                    "matched": obj.get("matched-at") or obj.get("matched_at"),
                    "url": obj.get("host") or obj.get("url"),
                    "description": (obj.get("info", {}).get("description") or "")[:200],
                })
            except json.JSONDecodeError:
                continue
        severity_counts = Counter(f["severity"] for f in findings)
        return {
            "findings": findings,
            "count": len(findings),
            "severity_breakdown": dict(severity_counts),
            "engine": "nuclei",
        }
    except subprocess.TimeoutExpired:
        return {"findings": [], "count": 0, "message": "nuclei scan timed out"}
    finally:
        Path(target_file).unlink(missing_ok=True)
