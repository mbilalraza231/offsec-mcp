"""
tools/alive.py — HTTP liveness probe.

Primary: httpx (ProjectDiscovery)
Fallback: Python requests (HEAD + GET, thread-pooled)
"""

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from config import find_tool

# We intentionally retry with verification disabled ONLY after a TLS error,
# because recon targets routinely have self-signed / expired certs. Every
# unverified hit is tagged `tls_verified: false` in the output so downstream
# consumers (the LLM, the saved JSON report) can see exactly which probes
# skipped cert validation. Normal browsing/production traffic is never sent
# through this code path.
TIMEOUT = 15

# Real browser User-Agent: CDN/WAF bot-walls (Vercel, Cloudflare) serve an
# identical 403 challenge to non-browser UAs, which hides real hosts. A
# browser UA elicits the true response so alive/dead and wildcard noise can
# be told apart.
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def check_alive(subdomains: list[str]) -> dict:
    if not subdomains:
        return {"alive": [], "dead": [], "stale": []}

    result = None
    httpx = find_tool("httpx")
    if httpx:
        try:
            payload = "\n".join(subdomains).encode()
            out = subprocess.check_output(
                [httpx, "-silent", "-json", "-status-code",
                 "-title", "-follow-redirects", "-no-color",
                 "-timeout", "8", "-retries", "2", "-threads", "30",
                 "-H", f"User-Agent: {BROWSER_UA}"],
                input=payload, stderr=subprocess.DEVNULL, timeout=TIMEOUT * 4,
            ).decode(errors="ignore")
            result = _parse_httpx(out, subdomains)
            # httpx can exit cleanly with ZERO lines when every host was slow
            # or momentarily unreachable. Don't trust an empty result -> fall
            # through to the Python probe, which retries over both schemes.
            if not out.strip():
                result = None
        except Exception:
            result = None

    if result is None:
        result = _python_probe(subdomains)

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
    alive, dead = [], []

    def probe(sub: str):
        headers = {"User-Agent": BROWSER_UA}
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            # First attempt: strict TLS verification (safe default).
            try:
                r = requests.get(url, timeout=6, verify=True,
                                 allow_redirects=True, headers=headers)
                return {"url": url, "status": r.status_code,
                        "title": _extract_title(r.text), "tls_verified": True}
            except requests.exceptions.SSLError:
                # Cert problem only — retry once without verification and mark it.
                try:
                    with urllib3.disable_warnings():
                        r = requests.get(url, timeout=6, verify=False,
                                         allow_redirects=True, headers=headers)
                    return {"url": url, "status": r.status_code,
                            "title": _extract_title(r.text), "tls_verified": False}
                except Exception:
                    continue
            except Exception:
                # Connection refused / DNS fail / timeout — try next scheme.
                continue
        return None

    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(probe, s): s for s in subdomains}
        for fut in as_completed(futures):
            sub = futures[fut]
            result = fut.result()
            if result:
                alive.append(result)
            else:
                dead.append(sub)

    return {"alive": alive, "dead": dead, "engine": "python-requests"}


def _extract_title(html: str) -> str:
    low = html.lower()
    i = low.find("<title>")
    j = low.find("</title>", i)
    if 0 <= i < j:
        return html[i + 7:j].strip()[:120]
    return ""
