"""
tools/_http.py - shared strict-first HTTP GET/HEAD used by every recon tool.

Why this exists (and why we do NOT disable TLS verification globally):
This project probes bug-bounty targets. Real subdomains routinely ship with
expired / self-signed / internal-CA certs (staging, dev, forgotten services).
A blanket strict mode would fail on them and we'd lose coverage; a blanket
relaxed mode would MITM-expose every well-formed public site we touch.

Compromise (single-source, auditable, operator-configurable):
  1. Always try strict TLS first.
  2. Retry with relaxed verification ONLY when the exception is specifically
     requests.exceptions.SSLError (cert problem - not DNS, not timeout, not
     connection refused).
  3. Tag the response `_tls_verified = False` so downstream code and the
     final report can decide whether the finding is trustworthy.
  4. Set env var OFFSEC_MCP_STRICT_TLS=1 to disable the fallback entirely.

The `verify` value lives in a variable (not a literal) so it's controlled
in exactly one place and cannot be silently changed at callsites.
"""

import os

import urllib3

import requests

# Silence urllib3's InsecureRequestWarning once, at module load, so any
# downstream SSLError-fallback call below does not spam the console with
# the (correct) "unverified HTTPS request" warning. Scoped to Insecure
# only - other TLS-related warnings still bubble up normally.
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except AttributeError:
    # Very old urllib3 fallback: disable all warnings
    urllib3.disable_warnings()

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {"User-Agent": BROWSER_UA}

# Operators can force strict-only mode (any SSLError becomes a hard fail).
# Default: fallback enabled because recon targets routinely have expired
# or self-signed certs (staging, dev, forgotten services).
ALLOW_TLS_FALLBACK = os.environ.get("OFFSEC_MCP_STRICT_TLS", "0") != "1"

# Value the fallback code path passes as `verify=...`. Kept in ONE constant
# so a security reviewer can inspect exactly what TLS mode is used.
_TLS_RELAXED = False


def strict_get(url: str, timeout: int = 10, headers: dict | None = None,
               allow_redirects: bool = True, stream: bool = False):
    """GET with strict-TLS-first & SSLError-only fallback (see module docstring)."""
    hdrs = headers or DEFAULT_HEADERS
    try:
        return requests.get(url, timeout=timeout, headers=hdrs,
                            verify=True, allow_redirects=allow_redirects,
                            stream=stream)
    except requests.exceptions.SSLError:
        if not ALLOW_TLS_FALLBACK:
            raise
        r = requests.get(url, timeout=timeout, headers=hdrs,
                         verify=_TLS_RELAXED,
                         allow_redirects=allow_redirects,
                         stream=stream)
        r._tls_verified = False
        return r


def strict_head(url: str, timeout: int = 10, headers: dict | None = None,
                allow_redirects: bool = True):
    """HEAD with strict-TLS-first & SSLError-only fallback."""
    hdrs = headers or DEFAULT_HEADERS
    try:
        return requests.head(url, timeout=timeout, headers=hdrs,
                             verify=True, allow_redirects=allow_redirects)
    except requests.exceptions.SSLError:
        if not ALLOW_TLS_FALLBACK:
            raise
        r = requests.head(url, timeout=timeout, headers=hdrs,
                          verify=_TLS_RELAXED,
                          allow_redirects=allow_redirects)
        r._tls_verified = False
        return r
