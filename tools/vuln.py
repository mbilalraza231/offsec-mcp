"""
tools/vuln.py - vulnerability scan with nuclei.

No pure-Python fallback - nuclei's template engine is irreplaceable.
If nuclei is missing, returns a clear message telling the user to install it.

Templates live on the SSD next to the binary (`bin/nuclei-templates/`)
so the whole setup stays portable. Bootstrap once:

    nuclei -update-templates -ud <ssd>/offsec-mcp/bin/nuclei-templates
"""

import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from config import BIN_DIR, find_tool

TIMEOUT = 300  # 5 min cap

LOCAL_TEMPLATES_DIR = BIN_DIR / "nuclei-templates"


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
                "nuclei not installed - run installers/install-tools.ps1 "
                "or download from https://github.com/projectdiscovery/nuclei/releases"
            ),
        }

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        target_file = f.name

    # Only pass -t when the SSD template dir actually exists and has
    # content. Otherwise let nuclei hit its own default and we surface
    # the exit=2 hint below.
    tmpl_args: list[str] = []
    if LOCAL_TEMPLATES_DIR.exists():
        try:
            if any(LOCAL_TEMPLATES_DIR.rglob("*.yaml")):
                tmpl_args = ["-t", str(LOCAL_TEMPLATES_DIR)]
        except OSError:
            tmpl_args = []

    try:
        proc = subprocess.run(
            [nuclei, "-l", target_file, "-silent", "-json", "-no-color",
             "-severity", "info,low,medium,high,critical"] + tmpl_args,
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
        result = {
            "findings": findings,
            "count": len(findings),
            "severity_breakdown": dict(severity_counts),
            "engine": "nuclei",
            "targets_scanned": len(targets),
        }
        # Exit 2 with no findings = nuclei failed to initialise, almost
        # always because templates are missing. Exit 0 with no findings
        # = legit "clean scan". Distinguish them.
        if proc.returncode != 0 and not findings:
            if proc.returncode == 2:
                result["engine_error"] = (
                    "nuclei exit=2 with no templates. Run once: "
                    f"nuclei -update-templates -ud {LOCAL_TEMPLATES_DIR}"
                )
            else:
                result["engine_error"] = (
                    f"nuclei exit={proc.returncode}; "
                    f"stderr preview: {(proc.stderr or '')[:250]}"
                )
        return result
    except subprocess.TimeoutExpired:
        return {
            "findings": [], "count": 0,
            "engine": "nuclei",
            "engine_error": (
                f"nuclei scan timed out after {TIMEOUT}s. Reduce target "
                "count or run standalone with narrower template set."
            ),
        }
    finally:
        Path(target_file).unlink(missing_ok=True)
