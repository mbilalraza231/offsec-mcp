"""
config.py — locates recon binaries and reports what's available.

Search order for each tool:
  1. ./bin/<tool>.exe   (installed by installers/install-tools.ps1)
  2. system PATH
  3. not found -> caller uses pure-Python fallback
"""

import os
import shutil
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BIN_DIR = BASE_DIR / "bin"
OUTPUT_DIR = BASE_DIR / "output"

# Ensure runtime folders exist
BIN_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# Popular recon tools we wrap
TOOLS = ["subfinder", "httpx", "dnsx", "nuclei", "amass"]


def _exe(name: str) -> str:
    return f"{name}.exe" if platform.system() == "Windows" else name


def find_tool(name: str) -> str | None:
    """Return absolute path to a recon binary, or None if not installed."""
    local = BIN_DIR / _exe(name)
    if local.exists():
        return str(local)
    return shutil.which(name)


def detect_tools() -> dict:
    """Report which tools are ready and which will run in fallback mode."""
    installed, fallback = {}, {}
    for tool in TOOLS:
        path = find_tool(tool)
        if path:
            installed[tool] = path
        else:
            fallback[tool] = (
                "not installed — run installers/install-tools.ps1 "
                "or the tool will use a Python fallback"
            )
    return {
        "installed": installed,
        "missing": fallback,
        "bin_dir": str(BIN_DIR),
        "platform": platform.system(),
    }
