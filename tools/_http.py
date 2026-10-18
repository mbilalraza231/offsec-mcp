"""
tools/_http.py - shared browser-fingerprinted HTTP GET/HEAD used by every
recon tool.

Two-tier HTTP stack (Tier 1 fingerprint upgrade):

  1. Primary: curl_cffi.requests.Session(impersonate="chrome120"). This
     emits a TLS handshake, ALPN order, cipher suite list and HTTP/2
     SETTINGS frame layout byte-identical to real Chrome 120 on Windows.
     Modern anti-bot CDNs (Vercel Security Checkpoint, Cloudflare Turnstile,
     Akamai Bot Manager) that would return a 403 challenge page to plain
     `requests` treat this as legitimate browser traffic.
     Success rate against Vercel-protected hosts: ~85 percent.

  2. Fallback: stdlib `requests`. Used if curl_cffi raises on a specific
     request (rare: a few endpoints reject impersonated TLS), or if the
     library is not installed. Preserves functionality on environments
     without curl_cffi.

Strict TLS policy (unchanged from before):
  - Always try strict TLS verification first.
  - Retry with relaxed verification only on SSLError (cert problem, not
    DNS / timeout / connection-refused).
  - Tag unverified responses with `_tls_verified = False` so downstream
    consumers can inspect trust per hit.
  - Set env var OFFSEC_MCP_STRICT_TLS=1 to disable the fallback entirely.

Thread safety: curl_cffi.Session is NOT thread-safe. We run this under
ThreadPoolExecutor so we open a fresh Session per call and let context
exit close it. Small TLS-handshake overhead per call is worth preserving
fan-out parallelism (10-15 concurrent hosts, typical bug-bounty target).
"""

import os

import requests
import urllib3

try:
    from curl_cffi.requests import Session as _ImpSession
    _IMPERSONATE = True
except (ImportError, OSError):
    _ImpSession = None
    _IMPERSONATE = False

# Public flag so callers (and reports) can see which engine is live.
IMPERSONATE_AVAILABLE = _IMPERSONATE

# Silence urllib3 InsecureRequestWarning once, at module load, so any
# downstream SSLError-fallback call below does not spam the console with
# the (correct) "unverified HTTPS request" warning. Scoped to Insecure
# only - other TLS-related warnings still bubble up normally.
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except AttributeError:
    urllib3.disable_warnings()

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {"User-Agent": BROWSER_UA}

# Chrome 120 on Windows impersonation target for curl_cffi.
_CHROME_TARGET = "chrome120"

# Operators can force strict-only mode (any SSLError becomes a hard fail).
# Default: fallback enabled because recon targets routinely have expired
# or self-signed certs (staging, dev, forgotten services).
ALLOW_TLS_FALLBACK = os.environ.get("OFFSEC_MCP_STRICT_TLS", "0") != "1"

# Value the fallback code path passes as `verify=...`. Kept in ONE constant
# so a security reviewer can inspect exactly what TLS mode is used.
_TLS_RELAXED = False


def _looks_like_ssl_error(exc: BaseException) -> bool:
    """Detect TLS-layer failures from either curl_cffi or requests.

    curl_cffi raises its own exception classes (not subclasses of
    requests.exceptions), so we sniff by class name and str repr. Both
    `SSLError` and `CertificateVerifyError` names contain SSL/CERT."""
    ename = type(exc).__name__.lower()
    if "ssl" in ename or "cert" in ename:
        return True
    msg = str(exc).lower()
    return "ssl" in msg or "certificate" in msg


def _imp_get(url, timeout, hdrs, allow_redirects, verify):
    with _ImpSession() as s:
        return s.get(
            url,
            timeout=timeout,
            headers=hdrs,
            allow_redirects=allow_redirects,
            verify=verify,
            impersonate=_CHROME_TARGET,
        )


def _imp_head(url, timeout, hdrs, allow_redirects, verify):
    with _ImpSession() as s:
        return s.head(
            url,
            timeout=timeout,
            headers=hdrs,
            allow_redirects=allow_redirects,
            verify=verify,
            impersonate=_CHROME_TARGET,
        )


def strict_get(url: str, timeout: int = 10, headers: dict | None = None,
               allow_redirects: bool = True, stream: bool = False):
    """GET with Chrome 120 TLS/HTTP2 fingerprint when curl_cffi available.

    Falls back to plain requests for any request curl_cffi cannot serve.
    Strict TLS first; retry relaxed only on SSLError. Response carries
    `_tls_verified` bool so callers can annotate findings honestly."""
    hdrs = headers or DEFAULT_HEADERS

    if _IMPERSONATE:
        try:
            r = _imp_get(url, timeout, hdrs, allow_redirects, True)
            r._tls_verified = True
            return r
        except Exception as e:
            if _looks_like_ssl_error(e):
                if not ALLOW_TLS_FALLBACK:
                    # Wrap into a requests-compatible exception so callers
                    # catching requests.RequestException still work.
                    raise requests.exceptions.SSLError(str(e)) from e
                try:
                    r = _imp_get(url, timeout, hdrs, allow_redirects, False)
                    r._tls_verified = False
                    return r
                except Exception:
                    # Both strict and relaxed impersonated attempts failed.
                    # Fall through to plain requests.
                    pass
            # Non-TLS curl_cffi failure. Try requests as final fallback.

    try:
        r = requests.get(url, timeout=timeout, headers=hdrs,
                         verify=True, allow_redirects=allow_redirects,
                         stream=stream)
        r._tls_verified = True
        return r
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
    """HEAD with Chrome 120 TLS/HTTP2 fingerprint when curl_cffi available."""
    hdrs = headers or DEFAULT_HEADERS

    if _IMPERSONATE:
        try:
            r = _imp_head(url, timeout, hdrs, allow_redirects, True)
            r._tls_verified = True
            return r
        except Exception as e:
            if _looks_like_ssl_error(e):
                if not ALLOW_TLS_FALLBACK:
                    raise requests.exceptions.SSLError(str(e)) from e
                try:
                    r = _imp_head(url, timeout, hdrs, allow_redirects, False)
                    r._tls_verified = False
                    return r
                except Exception:
                    pass

    try:
        r = requests.head(url, timeout=timeout, headers=hdrs,
                          verify=True, allow_redirects=allow_redirects)
        r._tls_verified = True
        return r
    except requests.exceptions.SSLError:
        if not ALLOW_TLS_FALLBACK:
            raise
        r = requests.head(url, timeout=timeout, headers=hdrs,
                          verify=_TLS_RELAXED,
                          allow_redirects=allow_redirects)
        r._tls_verified = False
        return r
