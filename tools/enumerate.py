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
from tools._http import strict_get

# Used to build query-string URLs when passing through strict_get
# (curl_cffi's Session accepts params too, but keeping URL construction
# explicit at callsites makes the query visible in every log line).
from urllib.parse import urlencode

TIMEOUT = 25

# Small, curated list of labels we know real organisations almost always
# stand up on their OWN infrastructure (different IP or CNAME than the
# wildcard pool). Used as a last-resort probe when dnsx-brute is
# wildcard-skipped, so we still catch mail / cpanel / admin etc. on
# targets like example.com where *.domain resolves to a Vercel edge pool
# but mail.domain has a CNAME to a totally separate webmail host.
# Kept to 40 labels: pure-DNS probes, ~1-2s wall time, high hit-rate.
CURATED_MUST_PROBE = (
    # mail / hosting
    "mail", "webmail", "smtp", "imap", "pop", "mx", "autodiscover",
    # control panels
    "cpanel", "whm", "webdisk", "directadmin", "plesk",
    # lifecycle envs
    "dev", "staging", "stage", "test", "uat", "beta", "preview",
    # auth / admin surfaces
    "admin", "dashboard", "portal", "api", "auth", "sso", "oauth",
    # dev infra
    "git", "gitlab", "gitea", "wiki", "docs", "status", "jenkins",
    # network / storage
    "cdn", "ftp", "sftp", "static", "assets", "files",
)

# A real browser User-Agent. Many CDN/WAF bot-walls (Vercel Security
# Checkpoint, Cloudflare) return an identical 403 challenge to non-browser
# UAs, masking real subdomains as noise. A browser UA gets the true response:
# real host -> 200 + unique page, non-existent -> 404 (e.g. Vercel
# 'DEPLOYMENT_NOT_FOUND'), which our status+title dedup can then separate.
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": BROWSER_UA}

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
                stderr=subprocess.DEVNULL, timeout=180,
            ).decode(errors="ignore")
            hits = {l.strip().lower()
                    for l in out.splitlines()
                    if domain in l and _is_valid_subdomain(l.strip(), domain)}
            if hits:
                collected |= hits
                source_detail["subfinder"] = sorted(hits)
                sources_ok.append(f"subfinder({len(hits)})")
            else:
                sources_fail.append("subfinder:empty")
        except subprocess.TimeoutExpired:
            # Tesla-scale targets: subfinder fans out to 50+ upstream APIs,
            # some of which are slow. 90s was too tight for orgs with 500+
            # subs. 180s now, but still record the miss so users know.
            sources_fail.append("subfinder:timeout(180s)")
        except Exception as e:
            sources_fail.append(f"subfinder:{e.__class__.__name__}")

    # --- 2-11. All HTTP passive sources in parallel ---
    with ThreadPoolExecutor(max_workers=10) as pool:
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

    # ---- 7. Active DNS brute (dnsx over full 110k wordlist) ----
    # Catches non-web subdomains (git, smtp, jenkins, redis, internal
    # tools) that have an A record but no HTTP server -> invisible to
    # httpx content-diff. Skipped automatically when the target has
    # wildcard DNS (see _dnsx_brute docstring for why).
    dnsx_words = _load_words_full()
    dnsx_hits, dnsx_wildcard = _dnsx_brute(domain, dnsx_words)
    if dnsx_wildcard:
        sources_fail.append("dnsx-brute:wildcard-skip")
    elif dnsx_hits:
        new = dnsx_hits - collected
        collected |= dnsx_hits
        if new:
            source_detail["dnsx-brute"] = sorted(new)
            sources_ok.append(f"dnsx-brute({len(new)})")
        else:
            sources_fail.append("dnsx-brute:no-new")
    else:
        sources_fail.append("dnsx-brute:empty-or-no-dnsx")

    # ---- 8. Altdns-style permutations (compound names not in wordlists) ----
    # Take every label discovered so far (from passive + dnsx) and generate
    # api1/api-1/dev-api/staging-api etc. Then verify via dnsx (fast).
    # Same wildcard-skip rule as _dnsx_brute above.
    perms = _permutations(collected, domain)
    if perms:
        perm_hits, perm_wildcard = _dnsx_brute(domain, perms, timeout=60)
        if perm_wildcard:
            sources_fail.append("permutations:wildcard-skip")
        elif perm_hits:
            new = perm_hits - collected
            collected |= perm_hits
            if new:
                source_detail["permutations"] = sorted(new)
                sources_ok.append(f"permutations({len(new)})")
            else:
                sources_fail.append("permutations:no-new")
        else:
            sources_fail.append("permutations:empty")
    else:
        sources_fail.append("permutations:no-labels")

    # ---- 9. Active HTTP verify (httpx content-diff on curated names) ----
    # Resolve common names via DNS. Detect wildcard by checking if ALL
    # candidates resolve to the same IPs. If wildcard: only keep names
    # with UNIQUE IP responses. If no wildcard: keep all that resolved.
    # This is how reconFTW/Amass/subfinder all work.
    active = _active_dns_verify(domain)
    if active:
        collected |= active
        source_detail["active-dns"] = sorted(active)
        sources_ok.append(f"active-dns({len(active)})")

    # ---- 9.5. Curated must-probe (bypass wildcard-skip) ----
    # When dnsx-brute is wildcard-skipped we still need to catch hosts
    # like mail, webmail, cpanel that live on totally SEPARATE infra
    # (different IP or CNAME than the wildcard pool) and would otherwise
    # be missed. Cheap: ~40 DNS queries, ~2s wall time. Also useful when
    # dnsx binary is not installed at all - fills the gap it would cover.
    wild_ips, wild_cnames = _discover_wildcard_pool(domain)
    wildcard_detected = bool(wild_ips or wild_cnames)
    must_hits = _curated_must_probe(domain, wild_ips, wild_cnames)
    new = must_hits - collected
    if new:
        collected |= new
        source_detail["must-probe"] = sorted(new)
        sources_ok.append(f"must-probe({len(new)})")
    else:
        sources_fail.append(
            "must-probe:no-new" if wildcard_detected else "must-probe:empty")

    # ---- 10. Wayback link-crawl with widened seed list ----
    # Seed from apex + www + up to 4 discovered hosts, so archived pages
    # on ANY known sub (not just base domain) contribute cross-links.
    crawl_seeds = [domain, f"www.{domain}"]
    for s in sorted(collected):
        if s in crawl_seeds:
            continue
        if len(crawl_seeds) >= 6:
            break
        crawl_seeds.append(s)
    crawled = _wayback_crawl(domain, seeds=crawl_seeds)
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

    # ---- Tier 3: confidence scoring ----
    # Reverse-map source_detail so each sub knows WHICH sources reported it.
    # A sub seen by 4 independent APIs is much more trustworthy than one seen
    # by a single flaky source. Bug bounty triagers care about corroboration.
    sources_by_sub: dict[str, list[str]] = {s: [] for s in subs}
    for sname, slist in source_detail.items():
        for sub in slist:
            if sub in sources_by_sub:
                sources_by_sub[sub].append(sname)
    source_count = {sub: len(srcs) for sub, srcs in sources_by_sub.items()}

    # Cap the returned list to avoid overwhelming the LLM context window.
    # Full list is saved via save_results; model only sees first 30 + count.
    MAX_RETURN = 30

    # Sort by confidence (source_count descending) so the most-corroborated
    # hosts are the ones that survive any downstream [:N] truncation. On
    # Tesla-scale targets (499 subs) this ensures active stages probe the
    # hosts seen by 2+ sources first, not the 1-source long tail.
    subs_sorted = sorted(
        subs, key=lambda s: source_count.get(s, 0), reverse=True)
    display = subs_sorted[:MAX_RETURN]

    # Per-sub detail bundle (host & which sources & corroboration count)
    subdomain_details = [
        {
            "host": s,
            "sources": sources_by_sub[s],
            "source_count": source_count[s],
        }
        for s in display
    ]

    # Aggregate stats so the caller can see quality of the result set
    confidence_summary = {
        "single_source": sum(1 for c in source_count.values() if c == 1),
        "multi_source": sum(1 for c in source_count.values() if c >= 2),
        "corroborated_3plus": sum(1 for c in source_count.values() if c >= 3),
    }

    return {
        "domain": domain,
        "count": len(subs),
        "showing": len(display),
        "subdomains": display,
        # Full sorted list for downstream pipeline stages (not returned to
        # the LLM as text; only internal tools like full_recon read this)
        "subdomains_all": subs_sorted,
        "subdomain_details": subdomain_details,
        "sources_by_sub": {s: sources_by_sub[s] for s in display},
        "confidence_summary": confidence_summary,
        "truncated": len(subs) > MAX_RETURN,
        # Wildcard DNS signal: True means *.domain resolves to a shared
        # pool. Users should trust HTTP content-diff over raw counts because
        # fake names will look real on DNS alone.
        "wildcard_dns": wildcard_detected,
        "wildcard_ip_pool": sorted(wild_ips)[:8],  # bounded for LLM context
        "sources_ok": sources_ok,
        "sources_failed": sources_fail,
        "per_source": {k: len(v) for k, v in source_detail.items()},
    }


# ---------------------------------------------------------------------------
# Individual passive source fetchers
# ---------------------------------------------------------------------------

def _crtsh(domain: str) -> set[str]:
    """Certificate Transparency logs via crt.sh.
    Returns common names from all issued certificates.

    crt.sh is notoriously slow on huge targets (Tesla, Google, Microsoft).
    Tesla alone has ~15k certs; response body can be 20MB+. We give crt.sh
    a 60s timeout instead of the shared TIMEOUT (25s).

    Internal retry (2 attempts, 4s sleep) on empty JSON list. crt.sh
    frequently returns `[]` under transient load even when records exist;
    a fresh request a few seconds later typically succeeds. The outer
    `_fetch_with_retry` wrapper doesn't help here because it only retries
    when the function RAISES; an empty list is a silent failure. We only
    retry on empty or JSON-decode errors (crt.sh sometimes returns an HTML
    error page that fails to parse). Real HTTP / network errors propagate
    so the caller's exception handling stays in control."""
    url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
    data = None
    for attempt in (1, 2):
        try:
            resp = requests.get(url, timeout=60, headers=HEADERS)
            resp.raise_for_status()
            try:
                data = resp.json()
            except ValueError:
                # HTML error page: retry once
                if attempt < 2:
                    time.sleep(4)
                    continue
                data = []
            if isinstance(data, list) and len(data) > 0:
                break  # got real results
            # empty list: retry once
            if attempt < 2:
                time.sleep(4)
                continue
        except requests.exceptions.RequestException:
            raise
    out: set[str] = set()
    for entry in (data or []):
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


def _wayback_crawl(domain: str, max_pages: int = 8,
                   seeds: list[str] | None = None) -> set[str]:
    """Wayback link-crawl: scrape archived HTML and extract subdomain refs.

    This finds hosts like `shop.target.com` that were NEVER archived
    themselves but appear as links/assets inside an archived homepage. The
    CDX API (source #6) only returns archived *URLs*; this digs the
    references out of the archived *page bodies*.

    seeds: hostnames whose archived pages we should crawl. Defaults to the
    apex + www only, but callers can pass in extra discovered hosts to
    widen the net (e.g. any sub that had an archived landing page).
    """
    out: set[str] = set()
    # 1. Find snapshots of the homepage (apex + www + caller-supplied seeds).
    # CDX returns oldest first, so we pull a wide range then keep the NEWEST.
    if seeds is None:
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


def _certspotter(domain: str) -> set[str]:
    """CertSpotter API - independent Certificate Transparency mirror.

    crt.sh 502s often and has no SLA; CertSpotter (SSLMate) queries a
    different set of CT logs so it fills gaps crt.sh leaves. Free, no auth,
    returns 10 requests/hour per IP unauthenticated - we call once per scan
    which is well within limits."""
    url = (f"https://api.certspotter.com/v1/issuances"
           f"?domain={quote(domain)}&include_subdomains=true"
           f"&expand=dns_names")
    resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
    if resp.status_code == 429:
        # Rate-limited -> caller's retry will back off and skip gracefully
        raise RuntimeError("certspotter rate-limited (429)")
    resp.raise_for_status()
    out: set[str] = set()
    for cert in resp.json():
        for name in cert.get("dns_names") or []:
            name = name.strip().lower().lstrip("*.")
            if name:
                out.add(name)
    return out


def _duckduckgo(domain: str) -> set[str]:
    """DuckDuckGo HTML search dork: `site:<domain> OR site:*.<domain>`.

    This surfaces subdomains Google/DDG has *indexed from live links*
    but that are missing from every cert-transparency / passive-DNS /
    Wayback source. Real bug bounty hunters use this exact query
    manually; automating it is a large coverage gain on wildcard-CDN
    targets (custom brand names like `docs.example.com` never appear
    in any wordlist or cert, only in pages that linked to them).

    Uses the html.duckduckgo.com HTML endpoint (no API key, unlike
    Google's Custom Search JSON). Skips redirect-wrapped result URLs
    whose hostnames look like `2Fxxx.domain.com` (those are percent-
    encoded slashes from DDG's `/l/?uddg=` link wrapper leaking into
    our regex - the clean form also appears in the same results).

    Fetches via strict_get so we emit a real Chrome 120 TLS fingerprint.
    DDG's rate limiter blocks plain Python requests and Go httpx pretty
    aggressively; Chrome-fingerprinted clients get served the actual
    HTML far more reliably."""
    url = ("https://html.duckduckgo.com/html/?"
           + urlencode({"q": f"site:{domain} OR site:*.{domain}"}))
    resp = strict_get(url, timeout=TIMEOUT, headers=HEADERS)
    if resp.status_code == 403:
        raise RuntimeError("duckduckgo rate-limited (403)")
    resp.raise_for_status()
    pattern = rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}"
    out: set[str] = set()
    for m in re.findall(pattern, resp.text):
        host = m.lower().strip(".")
        first_label = host.split(".")[0]
        # DDG wraps outbound links with %2F URL-encoded slashes. When our
        # regex grabs the string without decoding, the leading "2F" shows
        # up as part of the first label. Skip those; the clean host also
        # appears elsewhere in the same HTML.
        if re.fullmatch(r"2f[a-z0-9_-]+", first_label):
            continue
        if _is_valid_subdomain(host, domain):
            out.add(host)
    return out


def _bing(domain: str) -> set[str]:
    """Bing HTML search dork: `site:<domain> OR site:*.<domain>`.

    Second search-engine index alongside DuckDuckGo. Every engine crawls
    a slightly different slice of the web - Bing often has hosts Google
    and DDG don't (and vice-versa), especially recently-published product
    pages that index faster on Bing. Free, no API key (public HTML
    endpoint, not the Azure Search API). Skips Bing's own URL-tracker
    artifacts (`r.bing.com`, `www.bing.com/ck/`) that leak into our
    hostname regex.

    Uses strict_get so Bing sees a real Chrome TLS handshake and is far
    less likely to serve a 403 challenge page."""
    url = ("https://www.bing.com/search?"
           + urlencode({"q": f"site:{domain} OR site:*.{domain}"}))
    resp = strict_get(url, timeout=TIMEOUT, headers=HEADERS)
    if resp.status_code in (403, 429):
        raise RuntimeError(f"bing rate-limited ({resp.status_code})")
    resp.raise_for_status()
    pattern = rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}"
    out: set[str] = set()
    for m in re.findall(pattern, resp.text):
        host = m.lower().strip(".")
        if not _is_valid_subdomain(host, domain):
            continue
        # Drop Bing's own redirect-tracker hostnames and CDN edge nodes
        # that appear in <a href="..."> wrappers but aren't real target
        # subdomains (e.g. `www.bing.com` when scanning `bing.com`).
        if host.endswith(".bing.com") or host == "bing.com":
            continue
        if "bingcom" in host or "msedge" in host or "waws-prod" in host:
            continue
        out.add(host)
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
    ("crt.sh",         _crtsh,          3),
    ("certspotter",    _certspotter,    2),
    ("duckduckgo",     _duckduckgo,     2),
    ("bing",           _bing,           2),
    ("hackertarget",   _hackertarget,   2),
    ("alienvault",     _alienvault,     2),
    ("rapiddns",       _rapiddns,       2),
    ("wayback",        _wayback,        2),
    ("thc-org",        _thc_org,        2),
    ("bgp-he",         _bgp_he,         2),
]


# ---------------------------------------------------------------------------
# Active brute force - single-pass httpx with wildcard content-diffing
# httpx resolves + probes + returns content in ONE pass (much faster than
# doing dnsx then httpx separately). Curated service wordlist guarantees
# high-value names (shop, mail, api, ...) even when ranked past 9000
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
             "-timeout", "5", "-retries", "2", "-threads", "150",
             "-H", f"User-Agent: {BROWSER_UA}"],
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


def _python_probe_for_signature(hosts: list[str], timeout: int = 5,
                                max_workers: int = 25) -> dict:
    """Concurrent HTTP probe using strict_get (Chrome 120 TLS fingerprint).

    Returns `{host: (status_code, normalized_title_lower_truncated_60)}`
    for every host that gave any HTTP response. Hosts that failed DNS /
    connection / timeout are absent from the dict.

    Replaces the previous Go httpx subprocess call. Go's crypto/tls
    fingerprint is a bot tell Vercel and Cloudflare now check for; a
    Chrome-impersonated Python client passes those walls. strict_get's
    own internal fallback (curl_cffi strict -> curl_cffi relaxed ->
    requests strict -> requests relaxed) preserves functionality for
    users without curl_cffi installed or for hosts that reject
    impersonated TLS.

    25 threads (not 150 as in the Go path): a real Chrome session opens
    6-10 concurrent connections to a CDN, so 150 Chrome-fingerprinted
    requests from one residential IP itself looks impossible. 25 is
    still fast (~40s for 500 hosts) without triggering the
    too-many-concurrent-sessions detector.
    """
    from concurrent.futures import ThreadPoolExecutor
    probed: dict[str, tuple] = {}

    def _one(host: str):
        for scheme in ("https", "http"):
            try:
                r = strict_get(f"{scheme}://{host}", timeout=timeout)
            except Exception:
                continue
            # Title from first 20 KB. Real pages have <title> in head
            # near the top; avoids scanning 100 KB+ minified bundles.
            m = re.search(
                r"<title[^>]*>(.*?)</title>",
                r.text[:20000], re.I | re.S)
            title = (m.group(1).strip().lower()[:60]) if m else ""
            return host, (r.status_code, title)
        return host, None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for host, sig in pool.map(_one, hosts):
            if sig is not None:
                probed[host] = sig
    return probed


def _active_dns_verify(domain: str) -> set[str]:
    """Single-pass Python HTTP brute force with wildcard content-diffing.

    A wildcard CDN serves the SAME catch-all page (same status + title)
    for every name. A real subdomain serves a DISTINCT page. We probe
    baseline (random names) then keep only hosts whose (status, title)
    differs from the catch-all cluster.

    Chrome TLS fingerprint comes from strict_get's curl_cffi path, so
    Vercel and Cloudflare no longer serve us 403 bot-challenge pages on
    this stage. Previously used the Go httpx binary which was fast but
    got wall-blocked intermittently, dropping real hosts like
    shop.example.com from the run-to-run result set.

    Baseline calibration issue (fixed here): on a target behind an
    aggressive bot-wall, every baseline probe can receive the wall page
    instead of the real wildcard catchall. Memorising the wall sig is
    wrong because the wall is served identically to real and fake names
    downstream. The 404 wildcard catchall then looks unique against the
    wall baseline and dozens of fake names slip through in one run.

    Mitigations:
      - 10 baseline probes (was 6) so at least one is likely to break
        through an intermittent wall
      - Wall sigs are excluded from baseline_sigs when baselines respond
        normally, so a single walled probe cannot poison the calibration
      - Self-healing: if every baseline got walled or timed out, use
        the dominant non-wall sig among candidates as the catchall
      - Dominant-wall override: when the wall sig itself appears on 15+
        hosts (or half of all probed responses), Vercel's edge is serving
        the challenge to real and fake names uniformly. In that case the
        wall IS the catchall signature for this run and is added back
        to baseline_sigs so those names drop out too.
    """
    import random
    import string
    from collections import Counter
    from tools.alive import WALL_TITLE_SIGNATURES

    words = _load_words()
    candidates = [f"{w}.{domain}" for w in words]

    # 10 baseline probes (was 6). Higher chance at least one breaks
    # the wall and captures the true catchall signature.
    baseline_names = [
        f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{domain}"
        for _ in range(10)
    ]

    # One Python pass over baseline + candidates. 25 threads keeps wall
    # time around 40-90s for a ~500-name wordlist.
    all_hosts = candidates + baseline_names
    probed = _python_probe_for_signature(all_hosts, timeout=5, max_workers=25)
    if not probed:
        return set()

    def _is_wall(sig):
        """Bot-challenge pages: 403/429/503 with a challenge title.
        Served identically to real deployments and wildcard noise, so
        they can never act as the catchall baseline."""
        status, title = sig
        if status not in (403, 429, 503):
            return False
        return any(w in (title or "") for w in WALL_TITLE_SIGNATURES)

    # Baseline sigs: only from probes that broke through the wall.
    baseline_sigs = {
        probed[h] for h in baseline_names
        if h in probed and not _is_wall(probed[h])
    }

    sig_counts = Counter(probed.values())

    # Self-healing: if every baseline got walled or timed out, use the
    # most-common non-wall sig among candidates as the catchall. This
    # is exactly the case that produced the inflated 40-name active-dns
    # result on a Vercel wildcard target.
    if not baseline_sigs:
        for sig, n in sig_counts.most_common(20):
            if _is_wall(sig):
                continue
            if n >= 5:
                baseline_sigs.add(sig)
            break

    # Dominant wall = catchall behind wall.
    # Vercel's edge pipeline can challenge every request before routing
    # to the deployment. Both real apps and fake wordlist names then
    # return the exact same 403 wall page. In that case the wall sig IS
    # the catchall signature for this run, so we treat it as noise too.
    # Threshold: wall sig appears on >=15 hosts OR >=50% of probed.
    # The 15 floor protects small targets where only 3-5 real apps got
    # challenged (we still want those in the bot_walled bucket).
    total_probed = len(probed)
    for sig, n in sig_counts.most_common():
        if not _is_wall(sig):
            continue
        if n >= 15 or (total_probed >= 30 and n >= 0.5 * total_probed):
            baseline_sigs.add(sig)

    # Legacy dominant-cluster safety net, but only fires when the top
    # cluster is NOT a wall (walls handled above).
    if sig_counts:
        top_sig, top_n = sig_counts.most_common(1)[0]
        if (not _is_wall(top_sig)
                and top_n >= 0.5 * len(probed) and top_n >= 5):
            baseline_sigs.add(top_sig)

    # Error-status cluster override.
    # Any 4xx / 5xx signature observed on 5+ hosts is a shared handler
    # serving a catch-all page. Real apps occasionally cluster on 200
    # (e.g. 5 staging boxes with default nginx content) but never on
    # error statuses in numbers this big without being wildcard noise.
    # Catches cases like (404, '') from timeouts or bare 404 responses
    # that don't have the standard Vercel "404: NOT_FOUND" title.
    for sig, n in sig_counts.most_common(20):
        status = sig[0]
        if status and status >= 400 and n >= 5:
            baseline_sigs.add(sig)

    found: set[str] = set()
    for host, sig in probed.items():
        if host in baseline_names:
            continue
        if not _is_valid_subdomain(host, domain):
            continue
        if sig in baseline_sigs:
            continue  # catch-all page -> wildcard noise, skip
        # Wall sigs fall through and are kept. Downstream check_alive
        # places them in the bot_walled bucket honestly.
        found.add(host)

    # Include root/apex if it responded with non-noise content
    apex_sig = probed.get(domain)
    if apex_sig and apex_sig not in baseline_sigs:
        found.add(domain)

    return found


# ---------------------------------------------------------------------------
# DNS brute force + Altdns-style permutation
# ---------------------------------------------------------------------------
# Two coverage gaps the HTTP content-diff pass above can't fill:
#   1. Non-web subdomains (git, jenkins, smtp, redis, internal-tools)
#      often have an A record but serve NO HTTP on ports 80/443 -> httpx
#      never sees them. dnsx finds them purely via DNS resolution.
#   2. Compound real-world names (staging-api, api-v2, dev-mail) aren't
#      in any wordlist. Altdns-style permutation takes known labels and
#      generates cross-products the target actually uses.

PERMUTATION_MODIFIERS = (
    "dev", "test", "staging", "stage", "prod", "production",
    "api", "app", "internal", "portal", "admin", "backend",
    "v1", "v2", "v3", "new", "old", "beta", "alpha", "backup",
    "cdn", "edge", "cache", "lb", "us", "eu", "asia",
)


def _load_words_full() -> list[str]:
    """Full SecLists wordlist. Only single-label entries (no dots)."""
    try:
        with open(WORDLIST_PATH, encoding="utf-8", errors="ignore") as f:
            return [ln.strip().lower() for ln in f
                    if ln.strip() and "." not in ln.strip()]
    except FileNotFoundError:
        return []


def _run_dnsx(dnsx: str, hosts: list[str], timeout: int) -> dict:
    """Run dnsx with -a (A records). Returns {host: [ip, ...]}.

    Uses JSON output because dnsx emits ANSI color codes on Windows and
    its non-JSON `-a` mode prints only hostnames (no IPs) unless you also
    pass -resp; -json is unambiguous. Uses stdin instead of -l because
    dnsx's -l auto-wildcard detection over-filters and drops legitimate
    results. Threads/timeout kept moderate (50/5s/2 retries) because
    aggressive settings like 150 threads + 3s cause silent UDP failures
    on home broadband resolvers."""
    import json
    if not hosts:
        return {}
    result: dict[str, list[str]] = {}
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    try:
        payload = "\n".join(hosts).encode()
        out = subprocess.check_output(
            [dnsx, "-silent", "-json", "-a",
             "-t", "50", "-retry", "2", "-timeout", "5"],
            input=payload, stderr=subprocess.DEVNULL, timeout=timeout,
        ).decode(errors="ignore")
        for line in out.splitlines():
            line = ansi.sub("", line).strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (obj.get("host") or "").lower().rstrip(".")
            a = obj.get("a") or []
            if isinstance(a, str):
                a = [a]
            if host and a:
                result.setdefault(host, []).extend(a)
    except Exception:
        pass
    return result


def _dnsx_brute(domain: str, words: list[str],
                timeout: int = 180) -> tuple[set[str], bool]:
    """Brute force DNS resolution over a large wordlist.

    Returns (hits, has_wildcard).

    Wildcard handling: probe 5 random nonsense names first.
      - none resolve  -> domain has NO wildcard DNS. Every resolved
        candidate from the wordlist is a REAL hit.
      - all resolve   -> wildcard DNS is on. DNS alone cannot tell a
        real sub (e.g. shop.host) from a fake one (e.g. xyz.host)
        when both route through a CDN with a large shared IP pool. The
        only reliable signal is HTTP content-diff (which the downstream
        httpx stage handles). So we return an empty hit set and let the
        caller log the skip reason.
    """
    import random
    import string
    dnsx = find_tool("dnsx")
    if not dnsx or not words:
        return set(), False

    baseline = [
        f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{domain}"
        for _ in range(5)
    ]
    baseline_res = _run_dnsx(dnsx, baseline, timeout=15)
    has_wildcard = bool(baseline_res)
    if has_wildcard:
        # Wildcard + CDN IP pool makes DNS-only filtering unreliable.
        # The 5 baseline probes sample only a fraction of the pool; any
        # candidate that hits a not-yet-seen IP would be wrongly kept as
        # "real" (we've seen this generate 9 false www-<modifier> hits
        # on a Vercel-fronted domain). Skip and let HTTP verify handle it.
        return set(), True

    candidates = [f"{w}.{domain}" for w in words]
    resolved = _run_dnsx(dnsx, candidates, timeout=timeout)

    out: set[str] = set()
    for host, _ips in resolved.items():
        if host in baseline:
            continue
        if not _is_valid_subdomain(host, domain):
            continue
        out.add(host)
    return out, False


# ---------------------------------------------------------------------------
# Wildcard pool discovery and curated must-probe (bypass wildcard-skip)
# ---------------------------------------------------------------------------
# Problem: on targets like example.com, `*.example.com` is a wildcard A record
# pointing to Vercel's edge IP pool. Every real Vercel-hosted subdomain
# (docs, distributorpos) resolves to the SAME 4 IPs as every fake name
# (wb-randomnonce). DNS alone cannot distinguish them. Our existing
# `_dnsx_brute` correctly returns `wildcard_skip` here so we don't get
# 100% false positives from the wordlist. But that also skips real hosts
# like mail.example.com which have a CNAME to mail.mailprovider.example plus a
# totally different A record (45.8.227.100). The curated pass below catches
# those "different infra" hosts cheaply (40 DNS lookups, ~2s) while still
# leaving the wildcard-noise filtering to the HTTP content-diff stage.

def _discover_wildcard_pool(domain: str,
                            nonces: int = 15) -> tuple[set[str], set[str]]:
    """Resolve `nonces` random nonsense names in parallel. Return
    (ip_pool, cname_pool).

    We collect both A records AND CNAME targets because some wildcards
    are A-based (example.com: *.domain -> 4 shared IPs) and some are
    CNAME-based (e.g. *.hosted.io -> CNAME to proxy.hosted.io). The
    curated must-probe below uses these sets as "if it matches this,
    it's just wildcard noise" baselines.

    nonces defaults to 15 because edge CDNs like Vercel rotate 2 IPs
    per DNS response from a pool of 4+. With only 8 probes there is a
    ~(1/2)^8 = 0.4% chance any specific edge IP is missed by the pool;
    when that happens a wildcard-noise name resolves to the missed IP
    and looks like distinct infra to the strict-overlap filter. At 15
    probes the miss probability drops to ~(1/2)^15 ~= 3e-5 which is
    effectively never on real targets.

    Parallelised via ThreadPoolExecutor. Sequential dnspython on Windows
    was hitting 50s+ wall per call because each UDP query with a 3-5s
    lifetime adds up linearly across 16 lookups. With 8 workers the
    whole pass finishes in <5s regardless of resolver speed.

    Uses dnspython directly rather than dnsx so we always get the answer
    even when the target has no dnsx binary installed."""
    import random
    import string
    try:
        import dns.resolver
    except ImportError:
        return set(), set()

    def _one_nonce(_):
        n = "".join(random.choices(
            string.ascii_lowercase + string.digits, k=12))
        full = f"{n}.{domain}"
        ips, cnames = set(), set()
        for rtype in ("CNAME", "A"):
            try:
                r = dns.resolver.Resolver()
                r.timeout = 3
                r.lifetime = 5
                for rdata in r.resolve(full, rtype):
                    if rtype == "CNAME":
                        cnames.add(
                            rdata.target.to_text().rstrip(".").lower())
                    else:
                        ips.add(rdata.address)
            except Exception:
                continue
        return ips, cnames

    ip_pool: set[str] = set()
    cname_pool: set[str] = set()
    with ThreadPoolExecutor(max_workers=min(nonces, 8)) as pool:
        for ips, cnames in pool.map(_one_nonce, range(nonces)):
            ip_pool.update(ips)
            cname_pool.update(cnames)
    return ip_pool, cname_pool


def _curated_must_probe(domain: str, wild_ips: set[str],
                        wild_cnames: set[str]) -> set[str]:
    """Resolve CURATED_MUST_PROBE labels in parallel; return hosts that
    look real.

    A candidate is "real" (not wildcard noise) only if it has ZERO
    overlap with the wildcard pool on both dimensions:
      (a) its CNAME set shares no target with wild_cnames (or has no
          CNAME at all when wild_cnames is empty).
      (b) its A record set contains no IP that's in wild_ips.

    Strict zero-overlap rule matters because edge CDNs like Vercel
    rotate 2 IPs per response from a pool of 4+. If our nonce probes
    happened to miss one IP in that pool and a candidate resolves to it,
    "any IP outside pool" wrongly flags it as distinct infra. The
    safe rule is: keep only if the candidate looks genuinely
    different (e.g. mail.example.com -> 45.8.227.100 while wildcard
    pool is entirely Vercel edge IPs).

    If the domain has no wildcard (empty wild_ips and wild_cnames),
    ANY resolution is treated as real because there is no catchall to
    filter against.

    Parallelised with 20 workers. Sequential dnspython on Windows was
    hitting 240s+ wall on 40 labels (each query 3-6s); parallel it runs
    in ~5-10s.
    """
    try:
        import dns.resolver
    except ImportError:
        return set()

    no_wildcard = not wild_ips and not wild_cnames

    def _one_label(label):
        host = f"{label}.{domain}"
        cnames, ips = set(), set()
        for rtype in ("CNAME", "A"):
            try:
                r = dns.resolver.Resolver()
                r.timeout = 2
                r.lifetime = 4
                for rdata in r.resolve(host, rtype):
                    if rtype == "CNAME":
                        cnames.add(
                            rdata.target.to_text().rstrip(".").lower())
                    else:
                        ips.add(rdata.address)
            except Exception:
                continue
        if not cnames and not ips:
            return None
        if no_wildcard:
            return host
        # Strict rule: any overlap with wildcard pool = likely catchall noise
        if cnames and cnames & wild_cnames:
            return None
        if ips and ips & wild_ips:
            return None
        return host

    real: set[str] = set()
    with ThreadPoolExecutor(max_workers=20) as pool:
        for h in pool.map(_one_label, CURATED_MUST_PROBE):
            if h:
                real.add(h)
    return real


def _permutations(known_subs: set[str], domain: str,
                  max_out: int = 2000) -> list[str]:
    """Altdns-style candidate words derived from already-known labels.

    For each discovered single-label prefix (e.g. `api`, `dev`, `staging`)
    generate variants real orgs commonly use but wordlists miss:
      numbered       : api1, api-1, 1api, 1-api
      modifier cross : api-dev, dev-api, api-staging, staging-api, ...
      dotted nesting : dev-api -> dev.api (a nested sub of an existing sub)

    Returns candidate single-label prefixes ready to prepend to `domain`.
    Caller pipes them through dnsx / httpx like any other wordlist."""
    suffix = f".{domain}"
    labels: set[str] = set()
    for sub in known_subs:
        s = sub.lower()
        if not s.endswith(suffix):
            continue
        prefix = s[: -len(suffix)]
        if not prefix or "." in prefix:
            continue  # skip apex and multi-label hosts
        labels.add(prefix)

    seen: set[str] = set()
    out: list[str] = []
    for label in labels:
        for n in range(1, 4):
            for form in (f"{label}{n}", f"{label}-{n}",
                         f"{n}{label}", f"{n}-{label}"):
                if form not in seen:
                    seen.add(form)
                    out.append(form)
        for m in PERMUTATION_MODIFIERS:
            if m == label:
                continue
            for form in (f"{label}-{m}", f"{m}-{label}"):
                if form not in seen:
                    seen.add(form)
                    out.append(form)
        if "-" in label:
            dotted = label.replace("-", ".")
            if dotted not in seen:
                seen.add(dotted)
                out.append(dotted)
        if len(out) >= max_out:
            break
    return out[:max_out]
