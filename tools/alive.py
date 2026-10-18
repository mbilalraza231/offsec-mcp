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
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import find_tool
from tools._http import (
    BROWSER_UA,
    IMPERSONATE_AVAILABLE as _HAS_CURL_CFFI,
    strict_get,
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
    result = _split_stale(result)
    # Post-process: split 4xx responses whose title matches a known
    # bot-wall challenge page (Vercel Security Checkpoint, Cloudflare
    # Turnstile, Akamai Bot Manager) into `bot_walled`. Their bodies
    # are large enough (~15-40 KB of JS challenge code) to escape the
    # stale filter but they carry zero intel about the underlying app,
    # so downstream js_harvest / sensitive_files / waf_fingerprint
    # should skip them.
    result = _split_bot_walled(result)
    # Post-process: probe a nonsense hostname on the inferred apex and
    # move any alive host whose (status, title) exactly matches that
    # control response into `wildcard_http`. Catches Vercel wildcard
    # projects and generic Next.js starter 404 handlers that answer
    # every random name with an identical page. Without this filter,
    # admin.xinuty.com and test12345.xinuty.com both look like "real
    # deployments returning 404" because they share the same handler.
    return _split_wildcard_http(result, subdomains)


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


# ---------------------------------------------------------------------------
# Bot-wall title signatures (Fix A)
# ---------------------------------------------------------------------------
# Modern anti-bot CDNs serve a distinctive HTML challenge page when they
# decide a request is from a scanner. The pages all carry a title that
# is stable across requests and across hostnames, but their body length
# is 15-40 KB (well above our stale threshold of 500 bytes), so _split_stale
# alone doesn't catch them. This list captures the visible fingerprints.
WALL_TITLE_SIGNATURES = (
    "vercel security checkpoint",   # Vercel's anti-bot challenge
    "just a moment",                # Cloudflare classic interstitial
    "checking your browser",        # Cloudflare newer interstitial
    "attention required",           # Akamai Bot Manager
    "security checkpoint",          # Generic variant
    "verify you are human",         # Various
    "pardon our interruption",      # Fastly / Section.io
)


def _looks_like_wall(title: str) -> bool:
    """Case-insensitive substring match against known bot-wall titles."""
    t = (title or "").lower()
    return any(sig in t for sig in WALL_TITLE_SIGNATURES)


def _split_bot_walled(result: dict) -> dict:
    """Move 4xx responses whose title matches a known bot-wall signature
    into `bot_walled`. Their bodies are large (JS challenge page) so
    _split_stale misses them. Downstream stages (js_harvest, sensitive_files,
    waf_fingerprint) currently waste probes on the challenge HTML and get
    zero useful data. Splitting here saves that budget and makes the
    `alive_total` count honest about how many hosts we can actually see
    through to.
    """
    alive = result.get("alive", [])
    wall: list[dict] = []
    keep: list[dict] = []
    for a in alive:
        st = a.get("status") or 0
        if st >= 400 and _looks_like_wall(a.get("title", "")):
            wall.append(a)
        else:
            keep.append(a)
    result["alive"] = keep
    result["alive_total"] = len(keep)
    result["bot_walled"] = wall
    result["bot_walled_total"] = len(wall)
    return result


# Second-level suffixes that behave as "the TLD" for apex extraction.
# A naive "last 2 labels" rule would extract `co.uk` from
# `test.example.co.uk`, which is nonsense to probe. This set is the
# practical subset of the Public Suffix List you actually encounter on
# bug-bounty programs; full PSL is ~10k lines and overkill for our
# control-probe path.
MULTI_SUFFIX_TLDS = frozenset({
    # UK
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    # Australia / New Zealand
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    # East Asia
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "lg.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr", "pe.kr",
    "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn",
    # South / Southeast Asia
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk", "gok.pk", "gob.pk", "cto.pk",
    "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd", "ac.bd",
    "com.np", "net.np", "org.np", "gov.np", "edu.np", "ac.np",
    "com.lk", "net.lk", "org.lk", "gov.lk", "edu.lk", "ac.lk", "ltd.lk",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "co.id", "com.id", "net.id", "org.id", "go.id", "ac.id",
    "co.th", "or.th", "go.th", "in.th", "ac.th",
    # Americas
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "net.ar", "gob.ar", "edu.ar",
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    "com.pe", "gob.pe", "net.pe",
    # Europe / Middle East / Africa
    "com.ua", "kiev.ua", "lviv.ua",
    "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr", "k12.tr",
    "co.za", "org.za", "net.za", "gov.za", "edu.za",
    "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng", "name.ng",
    "com.gh", "net.gh", "org.gh",
    "co.tz", "or.tz", "go.tz", "ac.tz", "ne.tz",
    "co.ug", "or.ug", "go.ug", "ac.ug", "ne.ug", "sc.ug",
    "co.zw", "or.zw", "ac.zw", "go.zw",
    "com.eg", "org.eg", "net.eg",
    "co.il", "org.il", "net.il", "gov.il", "muni.il",
})


def _infer_apex(subdomains: list[str]) -> str | None:
    """Return the registrable apex (a.k.a. eTLD+1) of the first valid
    hostname in the list.

    Handles inputs like 'www.xinuty.com', 'https://xinuty.com', and
    'mail.xinuty.com' - all infer 'xinuty.com'. Recognises common
    two-part suffixes (co.uk, com.au, com.pk, etc.) so that a target
    like shop.example.co.uk correctly returns 'example.co.uk', not
    the nonsense string 'co.uk'. Returns None on empty or single-label
    input."""
    for s in subdomains:
        host = s.replace("http://", "").replace("https://", "")
        host = host.split("/", 1)[0].strip().lower()
        # Strip port if present
        host = host.split(":", 1)[0]
        labels = [l for l in host.split(".") if l]
        if len(labels) == 1:
            continue
        last_two = ".".join(labels[-2:])
        if len(labels) >= 3 and last_two in MULTI_SUFFIX_TLDS:
            return ".".join(labels[-3:])
        return last_two
    return None


def _http_wildcard_probe_sig(apex: str, timeout: int = 5) -> tuple | None:
    """Fetch a nonsense host on the apex and return (status, title_lower60)
    if it responds, else None. Uses strict_get so curl_cffi Chrome
    fingerprint is used (matching the real probes' transport).

    A wildcard-DNS and wildcard-project target (e.g. xinuty.com on Vercel
    with a catch-all Next.js app) answers ANY random name with an
    identical page. Comparing real subs against this control response
    separates 'genuinely deployed' from 'just the wildcard handler'."""
    import random
    import string
    nonce = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=16))
    probe = f"https://offsec-wildcard-{nonce}.{apex}"
    try:
        r = strict_get(probe, timeout=timeout)
    except Exception:
        return None
    m = re.search(
        r"<title[^>]*>(.*?)</title>",
        r.text[:20000], re.I | re.S)
    title = (m.group(1).strip().lower()[:60]) if m else ""
    return (r.status_code, title)


def _split_wildcard_http(result: dict, subdomains: list[str]) -> dict:
    """Move any alive host whose (status, title) exactly matches the
    control-probe response into `wildcard_http`. Only runs when at least
    one 4xx entry remains in the alive bucket (2xx responses are almost
    never wildcard noise). If the control probe itself fails or gets
    bot-walled (matching one of our wall signatures) we skip this pass
    to avoid false-flagging real subs."""
    alive = result.get("alive", [])
    four_x = [a for a in alive if (a.get("status") or 0) >= 400]
    if not four_x:
        result["wildcard_http"] = []
        result["wildcard_http_total"] = 0
        return result

    apex = _infer_apex(subdomains)
    if not apex:
        result["wildcard_http"] = []
        result["wildcard_http_total"] = 0
        return result

    sig = _http_wildcard_probe_sig(apex)
    if sig is None or _looks_like_wall(sig[1]):
        # Control probe failed or was bot-walled. Can't do a clean match
        # this run; leave everything in alive.
        result["wildcard_http"] = []
        result["wildcard_http_total"] = 0
        return result

    wildcard_hits: list[dict] = []
    keep: list[dict] = []
    for a in alive:
        a_sig = (a.get("status"), (a.get("title") or "").strip().lower()[:60])
        if (a.get("status") or 0) >= 400 and a_sig == sig:
            wildcard_hits.append(a)
        else:
            keep.append(a)
    result["alive"] = keep
    result["alive_total"] = len(keep)
    result["wildcard_http"] = wildcard_hits
    result["wildcard_http_total"] = len(wildcard_hits)
    result["wildcard_http_signature"] = {
        "status": sig[0], "title": sig[1]}
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
