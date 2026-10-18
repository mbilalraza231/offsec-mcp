"""
tools/alive.py - HTTP liveness probe.

Engine order (Tier 1 fingerprint upgrade):
  1. Primary: Python ThreadPool fan-out via tools/_http.strict_get, which
     uses curl_cffi.requests.Session(impersonate="chrome120") to emit a
     real Chrome 120 TLS handshake and HTTP/2 SETTINGS. Modern anti-bot
     CDNs (Vercel Security Checkpoint, Cloudflare Turnstile, Akamai Bot
     Manager) that return 403 walls to Go httpx and plain requests treat
     this as legitimate browser traffic.
  2. Fallback: httpx (ProjectDiscovery) Go binary, used only if the
     Python path returns an empty result set (rare: happens when every
     host timed out or was momentarily unreachable).
  3. Last resort: plain `requests` inside strict_get's fallback branch,
     used automatically when curl_cffi is not importable.

The Go binary is deliberately second: it is fast but its TLS fingerprint
is unique to Go's crypto/tls, which Vercel and Cloudflare now detect as
scanner traffic. The Python+curl_cffi combo is only marginally slower
across typical recon target sizes (< 200 hosts) but reliably passes
modern anti-bot walls.
"""

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import find_tool
from tools._http import (
    BROWSER_UA,
    IMPERSONATE_AVAILABLE as _HAS_CURL_CFFI,
    strict_get as _strict_get,
)

# Overall stage budget. Python path uses 6s per-request timeout; httpx
# binary uses 8s internally. Both fit comfortably inside TIMEOUT * 4.
TIMEOUT = 15


def check_alive(subdomains: list[str]) -> dict:
    if not subdomains:
        return {"alive": [], "dead": [], "stale": []}

    # --- Primary: Python + curl_cffi Chrome fingerprint -----------------
    # Best fingerprint match against modern anti-bot CDNs. Runs first so
    # Vercel / Cloudflare walls get through reliably.
    result = _python_probe(subdomains)

    # If the Python path returned nothing usable (all hosts DNS-failed or
    # timed out at the socket layer), fall back to the Go httpx binary
    # which has slightly different timeout behaviour and can salvage some
    # hosts on flaky networks.
    if not result.get("alive"):
        httpx = find_tool("httpx")
        if httpx:
            try:
                payload = "\n".join(subdomains).encode()
                out = subprocess.check_output(
                    [httpx, "-silent", "-json", "-status-code",
                     "-title", "-follow-redirects", "-no-color",
                     "-timeout", "8", "-retries", "2", "-threads", "15",
                     "-H", f"User-Agent: {BROWSER_UA}"],
                    input=payload, stderr=subprocess.DEVNULL,
                    timeout=TIMEOUT * 4,
                ).decode(errors="ignore")
                if out.strip():
                    result = _parse_httpx(out, subdomains)
            except Exception:
                pass

    # Post-process: detect wildcard DNS regardless of engine used
    result = _dedup_wildcard(result)
    # Post-process: split "server responded with 4xx + tiny body" into
    # a `stale` bucket so downstream stages don't waste probes on removed
    # deployments.
    return _split_stale(result)


def _split_stale(result: dict) -> dict:
    """Separate stale deployments from real alive hosts.

    A sub that returns 4xx with a tiny body (Vercel `The Deployment does
    not exist`, Netlify `Not Found`, Heroku `No such app`) has NO running
    application. httpx still lists it as "alive" because HTTP responded,
    but bug-bounty-wise there is nothing to inspect: no JS to harvest,
    no sensitive paths to probe, no WAF to fingerprint (the 404 page IS
    served by the CDN edge, but that tells us nothing about the app).

    Move such entries into a `stale` bucket so:
      - `alive_total` reflects genuinely usable hosts
      - LLM report shows a clean primary list plus a "watchlist" bucket
      - full_recon feeds only real alive URLs to waf/js/sensitive/nuclei

    Rule: status >= 400 AND length < 500 bytes => stale. Bot-wall
    challenge pages (Vercel Checkpoint, Cloudflare Turnstile) usually
    carry 1500-8000 bytes of JS to run the challenge. Those stay in
    `alive` because there IS a real app behind the wall; our later
    js_harvest bot-wall filter handles the skip at that stage instead.
    """
    alive = result.get("alive", [])
    real: list[dict] = []
    stale: list[dict] = []
    for a in alive:
        st = a.get("status") or 0
        ln = a.get("length")
        # `length` may be None if the probe engine did not report it.
        # Treat missing length as 0 (conservative -> flag as stale if 4xx).
        if ln is None:
            ln = 0
        if st >= 400 and ln < 500:
            stale.append(a)
        else:
            real.append(a)
    result["alive"] = real
    result["alive_total"] = len(real)
    result["stale"] = stale
    result["stale_total"] = len(stale)
    return result


def _parse_httpx(output: str, original: list[str]) -> dict:
    import json
    alive, seen = [], set()
    for line in output.splitlines():
        try:
            obj = json.loads(line)
            url = obj.get("url", "")
            seen.add(url)
            alive.append({
                "url": url,
                "status": obj.get("status_code"),
                "title": (obj.get("title") or "")[:120],
                "length": obj.get("content_length"),
            })
        except json.JSONDecodeError:
            continue
    dead = [
        s for s in original if s not in seen and f"https://{s}" not in seen]
    return {"alive": alive, "dead": dead, "engine": "httpx"}


def _dedup_wildcard(result: dict) -> dict:
    """If >70% of alive URLs share same (status,length), split them off as wildcard."""
    from collections import Counter
    alive = result.get("alive", [])
    if len(alive) < 5:
        return result
    signatures = Counter((a.get("status"), a.get("length")) for a in alive)
    most_common_sig, count = signatures.most_common(1)[0]
    if count / len(alive) <= 0.7 or count < 5:
        return result
    wildcard = [a for a in alive
                if (a.get("status"), a.get("length")) == most_common_sig]
    distinct = [a for a in alive
                if (a.get("status"), a.get("length")) != most_common_sig]
    return {
        "alive": distinct,
        "wildcard_catchall_count": len(wildcard),
        "wildcard_signature": {"status": most_common_sig[0],
                               "length": most_common_sig[1]},
        "dead": result.get("dead", []),
        "engine": result.get("engine", "unknown"),
        "note": (
            f"{len(wildcard)} subdomains returned identical response "
            f"(status={most_common_sig[0]}, length={most_common_sig[1]}). "
            f"This domain likely uses wildcard DNS. See 'wildcard_catchall_count'."
        ),
    }


def _python_probe(subdomains: list[str]) -> dict:
    """Concurrent HTTP probe using Chrome-fingerprinted strict_get.

    strict_get uses curl_cffi.requests.Session(impersonate="chrome120")
    under the hood when the library is installed, which reliably gets
    past Vercel Security Checkpoint and Cloudflare Turnstile that block
    plain requests and Go httpx. Falls back to requests when curl_cffi
    not available or when the specific URL rejects impersonated TLS.
    """
    alive, dead = [], []

    def probe(sub: str):
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            try:
                r = _strict_get(url, timeout=6, allow_redirects=True)
            except Exception:
                # Any non-SSL failure (DNS, refused, timeout) -> try next
                # scheme. SSLError-only relaxed retry already handled
                # inside strict_get itself.
                continue
            return {
                "url": url,
                "status": r.status_code,
                "title": _extract_title(r.text),
                "length": len(r.content),
                "tls_verified": getattr(r, "_tls_verified", True),
            }
        return None

    # 10 threads instead of the previous 15: a real Chrome session opens
    # 6-10 concurrent connections to a CDN, so 15 parallel Chrome-
    # fingerprinted requests from one IP can itself look bot-like on
    # strict detectors. 10 keeps throughput high without standing out.
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(probe, s): s for s in subdomains}
        for fut in as_completed(futures):
            sub = futures[fut]
            result = fut.result()
            if result:
                alive.append(result)
            else:
                dead.append(sub)

    engine = "python-curl_cffi" if _HAS_CURL_CFFI else "python-requests"
    return {"alive": alive, "dead": dead, "engine": engine}


def _extract_title(html: str) -> str:
    low = html.lower()
    i = low.find("<title>")
    j = low.find("</title>", i)
    if 0 <= i < j:
        return html[i + 7:j].strip()[:120]
    return ""
