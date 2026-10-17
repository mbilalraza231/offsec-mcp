"""
tools/archive.py - deep Wayback Machine (Internet Archive) URL harvest.

Different from the small Wayback call inside enumerate_subdomains (which
only extracts HOSTS). This returns EVERY URL archived on the target domain,
so you can spot:
  - Deprecated API endpoints still referenced in old mobile apps
  - Old admin panels moved to new subdomains
  - Historical /backup.sql or /env leaks that were taken down but still
    archived (bug-bounty triagers accept these as proof-of-concept)
  - Legacy staging/dev hosts that never made it into cert transparency

Pure HTTP to the free CDX API. No keys, no binaries.
"""

import re

from tools._http import strict_get

# URL patterns that are worth surfacing first (bug-bounty triage priorities)
INTERESTING_RE = re.compile(
    r"(?i)/(?:api|admin|internal|backup|bak|old|test|staging|stage|dev|"
    r"debug|actuator|private|secret|config|env|\.git|\.svn|swagger|graphql|"
    r"login|signin|dashboard|manage|panel|console|adminer|phpmyadmin|"
    r"cron|worker|jobs|ws|websocket|health|metrics|profiler|telescope|"
    r"horizon|_debug|\.env|\.git|\.aws)"
)

# File extensions we consider worth flagging regardless of path
INTERESTING_EXT_RE = re.compile(
    r"(?i)\.(?:sql|bak|old|orig|save|~|zip|tar|gz|tgz|7z|rar|"
    r"log|env|ini|conf|yml|yaml|lock|pem|key|crt|p12|pfx|"
    r"json|xml|old\.js)$"
)


def harvest_archived_urls(domain: str, max_urls: int = 5000,
                          from_year: int | None = None,
                          to_year: int | None = None,
                          timeout: int = 20) -> dict:
    """Ask Wayback Machine CDX for every URL ever archived on `domain`.

    Args:
        domain: apex domain like `example.com`. Do NOT prefix `*.` -
                CDX's matchType=domain already includes every subdomain.
        max_urls: cap how many CDX rows we pull (default 5000, plenty
                  for most targets; large orgs may have millions).
        from_year / to_year: filter archive window (e.g. only 2020+).
        timeout: per-request timeout. Wayback CDX can be slow.

    Returns:
        {
            "domain": str,
            "total_archived_urls": int,
            "unique_subdomains": [str, ...],
            "interesting_urls": [
                {"url","status","timestamp","reason"}  # why flagged
            ],
            "sample_urls": [str, ...],  # first 100 raw, unfiltered
            "note": str,
        }
    """
    if not domain or "." not in domain:
        return {"error": "domain required (e.g. 'example.com')"}

    params = {
        "url": domain,
        "matchType": "domain",
        "output": "text",
        "fl": "original,statuscode,timestamp,mimetype",
        "collapse": "urlkey",
        "limit": str(max_urls),
        "filter": "mimetype:(text/html|application/json|application/javascript|text/javascript|application/xml|text/xml):w",
    }
    if from_year:
        params["from"] = str(from_year)
    if to_year:
        params["to"] = str(to_year)

    resp = None
    try:
        resp = strict_get(
            f"http://web.archive.org/cdx/search/cdx?{urlencode_params(params)}",
            timeout=timeout,
        )
    except Exception as e:
        # Wayback CDX is famously flaky: 45s timeouts, 503s, mid-response
        # connection resets. Do NOT let a transient archive outage kill
        # a whole recon pipeline - return a graceful error dict instead.
        return {
            "domain": domain,
            "error": f"wayback CDX unavailable ({type(e).__name__}: {str(e)[:120]})",
            "total_archived_urls": 0,
            "unique_subdomains": [],
            "interesting_urls": [],
            "interesting_count": 0,
            "sample_urls": [],
            "note": "Wayback Machine timed out or errored; other recon "
                    "stages are unaffected. Retry later if this is important.",
        }
    if resp.status_code != 200:
        return {
            "error": f"wayback CDX returned {resp.status_code}",
            "domain": domain,
            "total_archived_urls": 0,
            "unique_subdomains": [],
            "interesting_urls": [],
            "interesting_count": 0,
            "sample_urls": [],
        }

    urls: list[dict] = []
    unique_subdomains: set[str] = set()
    interesting: list[dict] = []

    for line in resp.text.splitlines():
        parts = line.split()
        if not parts:
            continue
        original = parts[0]
        status = parts[1] if len(parts) >= 2 else ""
        timestamp = parts[2] if len(parts) >= 3 else ""
        try:
            host = re.sub(r"^https?://", "", original).split("/")[0].lower()
        except Exception:
            continue
        if domain.lower() not in host:
            continue
        unique_subdomains.add(host)
        entry = {
            "url": original, "status": status, "timestamp": timestamp,
        }
        urls.append(entry)

        # Flag as interesting if path or extension matches
        reasons = []
        if INTERESTING_RE.search(original):
            reasons.append("path-keyword")
        if INTERESTING_EXT_RE.search(original.split("?")[0]):
            reasons.append("sensitive-extension")
        if status in ("200", "301", "302", "307"):
            pass
        if reasons:
            entry["reason"] = ",".join(reasons)
            interesting.append(entry)

    return {
        "domain": domain,
        "total_archived_urls": len(urls),
        "unique_subdomains": sorted(unique_subdomains),
        "interesting_urls": interesting[:500],
        "interesting_count": len(interesting),
        "sample_urls": [u["url"] for u in urls[:100]],
        "note": (
            "Wayback Machine URLs are historical. Verify a live endpoint "
            "still exists before reporting - triagers require reproduction."
        ),
    }


def urlencode_params(params: dict) -> str:
    """Tiny local helper so we don't have to import urllib.parse just
    for one call (keeps module import cost minimal)."""
    from urllib.parse import urlencode
    return urlencode(params, quote_via=lambda x, *a, **kw: str(x))
