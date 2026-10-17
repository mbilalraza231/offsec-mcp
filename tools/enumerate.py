"""
tools/enumerate.py — multi-source passive subdomain enumeration.

Sources (all free, no API keys needed):
  1. subfinder binary - 50+ passive sources in one call
  2. crt.sh - Certificate Transparency logs
  3. HackerTarget - free passive DNS API
  4. AlienVault OTX - passive DNS
  5. RapidDNS - community subdomain DB
  6. Wayback Machine - archived URLs (CDX API)
  7. ip.thc.org - The Hacker Choice passive subdomains
  8. bgp.he.net - Hurricane Electric cert transparency

Design:
  - ALL HTTP sources run in parallel (ThreadPoolExecutor)
  - Per-source timeout + error isolation (one failure never blocks others)
  - Source attribution on every found subdomain
  - Automatic retry (2x) for flaky sources (crt.sh especially)
  - Only REAL passive intelligence - no brute force noise
"""

import os
import subprocess
import time
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import requests

from config import find_tool

TIMEOUT = 25
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; offsec-mcp/1.0)"}

# No brute-force. Only passive intelligence sources (no false positives).
# Sources defined after PASSIVE_SOURCES below.


def enumerate_subdomains(domain: str) -> dict:
    """Query all passive sources in parallel, merge unique subdomains."""
    domain = domain.strip().lower().lstrip(".")
    if not domain or "." not in domain:
        return {"domain": domain, "sources_ok": [], "sources_failed": [],
                "count": 0, "subdomains": [],
                "message": "Invalid domain format. Use: example.com"}

    collected: set[str] = set()
    source_detail: dict[str, list[str]] = {}  # source -> list of found subs
    sources_ok: list[str] = []
    sources_fail: list[str] = []

    # --- 1. subfinder binary (fastest, covers 50+ sources internally) ---
    sf = find_tool("subfinder")
    if sf:
        try:
            out = subprocess.check_output(
                [sf, "-d", domain, "-silent", "-all"],
                stderr=subprocess.DEVNULL, timeout=90,
            ).decode(errors="ignore")
            hits = {l.strip().lower()
                    for l in out.splitlines()
                    if domain in l and _is_valid_subdomain(l.strip(), domain)}
            if hits:
                collected |= hits
                source_detail["subfinder"] = sorted(hits)
                sources_ok.append(f"subfinder({len(hits)})")
        except subprocess.TimeoutExpired:
            sources_fail.append("subfinder:timeout(90s)")
        except Exception as e:
            sources_fail.append(f"subfinder:{e.__class__.__name__}")

    # --- 2-8. All HTTP sources in parallel ---
    with ThreadPoolExecutor(max_workers=7) as pool:
        future_map = {
            pool.submit(_fetch_with_retry, fn, domain, retries):
            (name, fn, retries)
            for name, fn, retries in PASSIVE_SOURCES
        }
        for fut in as_completed(future_map):
            name = future_map[fut][0]
            try:
                subs = fut.result()
                if subs:
                    valid = {s for s in subs if _is_valid_subdomain(s, domain)}
                    collected |= valid
                    if valid:
                        source_detail[name] = sorted(valid)
                        sources_ok.append(f"{name}({len(valid)})")
                else:
                    sources_fail.append(f"{name}:empty")
            except Exception:
                sources_fail.append(f"{name}:failed")

    # ---- 7. Active DNS verification (smart brute force) ----
    # Resolve common names via DNS. Detect wildcard by checking if ALL
    # candidates resolve to the same IPs. If wildcard: only keep names
    # with UNIQUE IP responses. If no wildcard: keep all that resolved.
    # This is how reconFTW/Amass/subfinder all work.
    active = _active_dns_verify(domain)
    if active:
        collected |= active
        source_detail["active-dns"] = sorted(active)
        sources_ok.append(f"active-dns({len(active)})")

    # ---- 8. Wayback link-crawl (finds hosts referenced in archived pages) ----
    crawled = _wayback_crawl(domain)
    if crawled:
        new = crawled - collected
        collected |= crawled
        if new:
            source_detail["wayback-crawl"] = sorted(crawled)
            sources_ok.append(f"wayback-crawl({len(crawled)})")
        else:
            sources_fail.append("wayback-crawl:no-new")
    else:
        sources_fail.append("wayback-crawl:empty")

    subs = sorted(collected)

    # Cap the returned list to avoid overwhelming the LLM context window.
    # Full list is saved via save_results; model only sees first 30 + count.
    MAX_RETURN = 30
    display = subs[:MAX_RETURN] if len(subs) > MAX_RETURN else subs

    return {
        "domain": domain,
        "count": len(subs),
        "showing": len(display),
        "subdomains": display,
        "truncated": len(subs) > MAX_RETURN,
        "sources_ok": sources_ok,
        "sources_failed": sources_fail,
        "per_source": {k: len(v) for k, v in source_detail.items()},
    }


# ---------------------------------------------------------------------------
# Individual passive source fetchers
# ---------------------------------------------------------------------------

def _crtsh(domain: str) -> set[str]:
    """Certificate Transparency logs via crt.sh.
    Returns common names from all issued certificates."""
    url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    out: set[str] = set()
    for entry in resp.json():
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name:
                out.add(name)
    return out


def _hackertarget(domain: str) -> set[str]:
    """HackerTarget free hostsearch API. Returns hostname,IP pairs."""
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    out: set[str] = set()
    for line in resp.text.splitlines():
        if "error" in line.lower():
            break
        parts = line.split(",")
        if parts and parts[0].strip():
            out.add(parts[0].strip().lower())
    return out


def _alienvault(domain: str) -> set[str]:
    """AlienVault OTX passive DNS. No API key needed for basic queries."""
    url = (f"https://otx.alienvault.com/api/v1/"
           f"indicators/domain/{quote(domain)}/passive_dns")
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    out: set[str] = set()
    data = resp.json()
    for entry in data.get("passive_dns", []):
        host = entry.get("hostname", "").strip().lower()
        if host:
            out.add(host)
    return out


def _rapiddns(domain: str) -> set[str]:
    """RapidDNS.io community subdomain database."""
    url = f"https://rapiddns.io/subdomain/{quote(domain)}?full=1"
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    pattern = rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}"
    return {m.lower() for m in re.findall(pattern, resp.text)}


def _wayback(domain: str) -> set[str]:
    """Internet Archive Wayback Machine CDX API.
    Finds subdomains from historically archived URLs."""
    url = (f"http://web.archive.org/cdx/search/cdx"
           f"?url=*.{quote(domain)}&output=text&fl=original"
           f"&collapse=urlkey&limit=500")
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    pattern = rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}"
    out: set[str] = set()
    for line in resp.text.splitlines():
        try:
            # Extract hostname from URL
            if "://" in line:
                host = line.split("://", 1)[1].split("/", 1)[0]
                host = host.split(":")[0].lower()  # remove port
                if domain in host:
                    out.add(host)
        except (IndexError, ValueError):
            continue
    return out


def _wayback_crawl(domain: str, max_pages: int = 8) -> set[str]:
    """Wayback link-crawl: scrape archived HTML and extract subdomain refs.

    This finds hosts like `restaurant.target.com` that were NEVER archived
    themselves but appear as links/assets inside an archived homepage. The
    CDX API (source #6) only returns archived *URLs*; this digs the
    references out of the archived *page bodies*.
    """
    out: set[str] = set()
    # 1. Find snapshots of the homepage (apex + www). CDX returns oldest
    # first, so we pull a wide range then keep the NEWEST max_pages.
    seeds = [domain, f"www.{domain}"]
    seen_ts: set[str] = set()
    snapshots: list[tuple[str, str]] = []  # (timestamp, original_url)
    for seed in seeds:
        try:
            url = ("http://web.archive.org/cdx/search/cdx"
                   f"?url={quote('http://' + seed, safe='')}&matchType=exact"
                   "&output=text&fl=timestamp,original"
                   "&collapse=digest&filter=statuscode:200&limit=200")
            resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            if resp.status_code != 200:
                continue
            rows = []
            for line in resp.text.splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[1].startswith("http"):
                    rows.append((parts[0], parts[1]))
            # keep newest (timestamps sort lexicographically = chronologically)
            rows.sort(key=lambda x: x[0], reverse=True)
            for ts, orig in rows[:max_pages]:
                if ts not in seen_ts:
                    seen_ts.add(ts)
                    snapshots.append((ts, orig))
        except Exception:
            continue

    # newest first across both seeds
    snapshots.sort(key=lambda x: x[0], reverse=True)
    snapshots = snapshots[:max_pages * 2]

    host_re = re.compile(rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}")
    # 2. Fetch each snapshot's raw body (id_ = original, un-rewritten content)
    fetched = 0
    for ts, orig in snapshots:
        if fetched >= max_pages:
            break
        try:
            raw = f"http://web.archive.org/web/{ts}id_/{orig}"
            resp = requests.get(raw, timeout=TIMEOUT, headers=HEADERS)
            if resp.status_code != 200 or not resp.text:
                continue
            fetched += 1
            for host in host_re.findall(resp.text):
                host = host.lower().strip(".")
                if _is_valid_subdomain(host, domain):
                    out.add(host)
        except Exception:
            continue
    return out


def _thc_org(domain: str) -> set[str]:
    """ip.thc.org - The Hacker Choice passive subdomain database.
    Used by reconFTW. Free, no key."""
    url = f"https://ip.thc.org/sb/{quote(domain)}"
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    out: set[str] = set()
    for line in resp.text.splitlines():
        line = line.strip().lower()
        if line and not line.startswith(";;") and domain in line:
            # May be just hostnames or host,ip format
            host = line.split(",")[0].strip()
            if host and _is_valid_hostname(host):
                out.add(host)
    return out


def _bgp_he(domain: str) -> set[str]:
    """bgp.he.net - Hurricane Electric certificate transparency.
    Free, no key. Used by reconFTW for CT log queries."""
    url = f"https://bgp.he.net/certs/api/list?domain={quote(domain)}"
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    resp.raise_for_status()
    out: set[str] = set()
    try:
        data = resp.json()
        for entry in data.get("domains", []):
            name = entry.get("domain", "").strip().lower().lstrip("*.")
            if name:
                out.add(name)
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    return out


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _fetch_with_retry(fn, domain: str, retries: int = 2):
    """Call fn with retries and exponential backoff. Returns set or empty set."""
    for attempt in range(retries):
        try:
            result = fn(domain)
            if result is not None:
                return result
        except Exception:
            if attempt < retries - 1:
                time.sleep(2 * (attempt + 1))  # 2s, 4s backoff
    return set()


def _is_valid_subdomain(host: str, domain: str) -> bool:
    """Ensure host is actually a subdomain of target domain."""
    if not host or not domain:
        return False
    return host == domain or host.endswith(f".{domain}")


def _is_valid_hostname(host: str) -> bool:
    """Basic hostname validation."""
    return bool(re.match(r"^[a-zA-Z0-9._-]+$", host))


# ---------------------------------------------------------------------------
# Source registry (defined after all functions so references resolve)
# ---------------------------------------------------------------------------
PASSIVE_SOURCES = [
    ("crt.sh",        _crtsh,         3),
    ("hackertarget",  _hackertarget,  2),
    ("alienvault",    _alienvault,    2),
    ("rapiddns",      _rapiddns,      2),
    ("wayback",       _wayback,       2),
    ("thc-org",       _thc_org,       2),
    ("bgp-he",        _bgp_he,        2),
]


# ---------------------------------------------------------------------------
# Active brute force - single-pass httpx with wildcard content-diffing
# httpx resolves + probes + returns content in ONE pass (much faster than
# doing dnsx then httpx separately). Curated service wordlist guarantees
# high-value names (restaurant, mail, api, ...) even when ranked past 9000
# in the raw SecLists file.
# ---------------------------------------------------------------------------

WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "wordlists", "subdomains-110k.txt",
)
SERVICES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "wordlists", "services.txt",
)


def _load_words(limit_common: int = 250) -> list[str]:
    """Merge curated service names + a small top-ranked common slice.

    We intentionally keep this tight (~500 names). Brute-forcing the full
    110k list over HTTP takes many minutes; 500 high-value names run in ~20s
    and cover the overwhelming majority of real-world subdomains.
    """
    words: list[str] = []
    try:
        with open(SERVICES_PATH, encoding="utf-8", errors="ignore") as f:
            words += [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        pass
    try:
        with open(WORDLIST_PATH, encoding="utf-8", errors="ignore") as f:
            words += [line.strip() for line in f if line.strip()][
                :limit_common]
    except FileNotFoundError:
        pass
    # dedup preserving order
    seen: set[str] = set()
    out: list[str] = []
    for w in words:
        wl = w.lower()
        if wl and wl not in seen:
            seen.add(wl)
            out.append(wl)
    return out


def _httpx_probe(httpx: str, hosts: list[str], timeout: int) -> dict:
    """Run httpx once, return {host: (status, length, title)} for alive hosts."""
    import json
    result: dict[str, tuple] = {}
    if not hosts:
        return result
    try:
        payload = "\n".join(hosts).encode()
        out = subprocess.check_output(
            [httpx, "-silent", "-json", "-status-code", "-title",
             "-content-length", "-follow-redirects", "-no-color",
             "-timeout", "5", "-retries", "2", "-threads", "150"],
            input=payload, stderr=subprocess.DEVNULL, timeout=timeout,
        ).decode(errors="ignore")
        for line in out.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("host", "")
            host = re.sub(r'^https?://', '', url).split('/')[0].lower()
            if not host:
                continue
            # Signature = status + normalized title. We do NOT use
            # content_length because CDNs (Vercel, Cloudflare) embed a
            # per-request nonce that shifts the byte count by +/-25, making
            # identical catch-all pages look unique and defeating dedup.
            title = (obj.get("title") or "").strip().lower()[:60]
            sig = (obj.get("status_code"), title)
            result[host] = sig
    except Exception:
        pass
    return result


def _active_dns_verify(domain: str) -> set[str]:
    """Single-pass httpx brute force with wildcard content-diffing.

    A wildcard CDN serves the SAME catch-all page (same status + title) for
    every name. A real subdomain serves a DISTINCT page. We probe baseline
    (random names), then keep only hosts whose (status, title) differs from
    the catch-all cluster.
    """
    import random
    import string
    from collections import Counter

    httpx = find_tool("httpx")
    if not httpx:
        return set()

    words = _load_words()
    candidates = [f"{w}.{domain}" for w in words]

    # Baseline probes (random nonsense names) capture the catch-all signature
    baseline_names = [
        f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{domain}"
        for _ in range(6)
    ]

    # Run baseline + candidates in one httpx pass for speed
    all_hosts = candidates + baseline_names
    probed = _httpx_probe(httpx, all_hosts, timeout=200)
    if not probed:
        return set()

    # Signatures returned by nonsense names = the catch-all noise
    baseline_sigs = {probed[h] for h in baseline_names if h in probed}

    # Also treat the dominant cluster as catch-all (robust when baseline
    # names happen not to respond but the wildcard still serves wordlist hits)
    sig_counts = Counter(probed.values())
    if sig_counts:
        top_sig, top_n = sig_counts.most_common(1)[0]
        if top_n >= 0.5 * len(probed) and top_n >= 5:
            baseline_sigs.add(top_sig)

    found: set[str] = set()
    for host, sig in probed.items():
        if host in baseline_names:
            continue
        if not _is_valid_subdomain(host, domain):
            continue
        if sig in baseline_sigs:
            continue  # catch-all page -> wildcard noise, skip
        found.add(host)

    # Include root/apex if it responded with non-noise content
    apex_sig = probed.get(domain)
    if apex_sig and apex_sig not in baseline_sigs:
        found.add(domain)

    return found
