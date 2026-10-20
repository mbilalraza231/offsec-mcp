"""
tools/js_harvest.py - deep-fetch HTML + JavaScript on alive subdomains and
regex-extract EVERY host, endpoint and possible secret referenced in the code.

Why this tool exists: top bug bounty hunters do this manually every day. Real
subdomains like `api.internal.example.com` and staging URLs are NEVER in
cert-transparency logs or search-engine indexes; they only exist INSIDE the
production app's JS bundle. Same for leaked API keys, JWTs, AWS credentials,
and hidden endpoints like `/internal/v1/refund`.

Pure Python. No API key. No binary. Uses same browser UA trick as the rest
of this project to bypass CDN bot-walls.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests

from tools._http import BROWSER_UA, DEFAULT_HEADERS as HEADERS, strict_get as _get

# Any hostname-looking token in text (sub.domain & TLD)
SUBDOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,})\b"
)

# Endpoint-like tokens: strings starting with /api /admin /internal /v[0-9]+ etc.
ENDPOINT_RE = re.compile(
    r"""["'`](/(?:api|admin|internal|v[0-9]+|auth|oauth|debug|actuator|"""
    r"""health|metrics|graphql|rest|private|backend|service|webhook|"""
    r"""callback|upload|download|files|export|import|sync|jobs|tasks|"""
    r"""cron|admin-panel|manage|panel|dashboard)[/\s"'`?][^"'`\s]{0,120})["'`]"""
)

# Well-known secret formats. Text truncated before returning so we do NOT
# exfiltrate real credential material - user sees "kind + first 12 chars"
# and where it was found; they can verify by opening the JS URL themselves.
SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "aws_secret_key": re.compile(
        r"(?i)aws(.{0,20})?['\"][0-9a-fA-F/+]{40}['\"]"
    ),
    "github_token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
    "google_api_key": re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    "slack_token": re.compile(r"\b(xox[bpars]-[A-Za-z0-9-]{10,})\b"),
    "stripe_live_secret": re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})\b"),
    "stripe_publishable": re.compile(r"\b(pk_(?:live|test)_[A-Za-z0-9]{20,})\b"),
    "jwt": re.compile(
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b"
    ),
    "private_key_pem": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "generic_secret_assignment": re.compile(
        r"""(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)"""
        r"""["']?\s*[:=]\s*["']([A-Za-z0-9_\-./+]{16,})["']"""
    ),
}

# Subdomains we should NOT report as discoveries - these are third-party CDN /
# analytics / widget hosts referenced in almost every web app.
NOISE_HOSTS = {
    "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com", "code.jquery.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "www.google.com",
    "www.googletagmanager.com", "google-analytics.com", "analytics.google.com",
    "connect.facebook.net", "platform.twitter.com", "www.youtube.com",
    "youtube.com", "youtu.be", "player.vimeo.com", "vimeo.com",
    "maps.googleapis.com", "maps.gstatic.com", "accounts.google.com",
    "oauth.reddit.com", "www.reddit.com", "reddit.com",
    "cdnjs.cloudflare.com", "ajax.cloudflare.com",
    "challenges.cloudflare.com", "static.cloudflareinsights.com",
    "s3.amazonaws.com", "s3-external-1.amazonaws.com",
    "cdn.tailwindcss.com", "stackpath.bootstrapcdn.com",
    "use.fontawesome.com", "kit.fontawesome.com",
    "www.recaptcha.net", "recaptcha.net",
}

# Whitelist of real TLDs. Our hostname regex matches things like
# `a.animate` or `Math.pow` in JS code (which look like sub.domain.tld).
# Requiring the final label to be a real TLD filters out 99% of that noise
# while keeping genuine discoveries.
VALID_TLDS = {
    # generic gTLDs
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz",
    "xyz", "online", "site", "store", "tech", "space", "website",
    "live", "life", "news", "shop", "club", "network", "systems",
    "digital", "media", "photo", "photography", "studio", "agency",
    "company", "solutions", "services", "rocks", "win", "bid",
    "party", "science", "download", "stream", "click", "link",
    # popular ccTLDs used as tech brands
    "io", "co", "ai", "in", "me", "tv", "gg", "sh", "so", "im", "fm",
    "app", "dev", "cloud", "email", "host", "page", "link", "codes",
    # Europe
    "eu", "uk", "de", "fr", "es", "pt", "nl", "be", "ch", "se", "no",
    "dk", "fi", "pl", "cz", "sk", "hu", "ro", "bg", "gr", "at", "it",
    "ie", "is", "lu", "mt", "cy", "hr", "si", "rs", "ba", "mk", "al",
    # East / North Asia
    "ru", "ua", "by", "kz", "ge", "am", "az", "jp", "kr", "cn", "tw",
    "hk", "sg", "my", "th", "vn", "id", "ph", "kp", "mn",
    # South Asia
    "pk", "bd", "lk", "np", "bt", "mv", "af",
    # Oceania
    "au", "nz", "fj", "pg", "ws", "to", "sb", "vu",
    # Americas
    "ca", "mx", "us", "gt", "bz", "cr", "pa", "cu", "jm", "ht", "do",
    "pr", "bs", "bb", "tt", "gd", "lc", "vc", "ag", "dm", "kn", "ai",
    "vg", "vi", "aw", "cw", "sx", "bq", "an",
    "ar", "cl", "pe", "ec", "co", "ve", "bo", "gy", "sr", "gf", "br",
    "py", "uy",
    # Africa
    "za", "na", "bw", "zw", "zm", "mw", "mz", "sz", "ls", "mg", "mu",
    "sc", "dj", "so", "er", "et", "ke", "tz", "ug", "rw", "bi", "cf",
    "td", "ne", "ml", "sn", "gm", "gw", "gn", "sl", "lr", "ci", "bf",
    "gh", "tg", "bj", "ng", "cm", "gq", "ga", "cg", "cd", "ao", "cv",
    "st", "eh", "ma", "tn", "dz", "ly", "eg", "ss", "sd",
    # Middle East
    "sa", "ye", "om", "ae", "qa", "bh", "kw", "jo", "lb", "sy", "iq",
    "ir", "il", "tr",
    # Special
    "asia", "tel", "travel", "jobs", "mobi", "post", "coop", "museum",
    "aero", "xxx", "adult", "pro", "arpa",
    # New gTLDs often seen in recon
    "ninja", "guru", "pizza", "cafe", "kitchen", "bar", "pub", "run",
    "world", "now", "today", "tips", "care", "fyi", "wiki", "how",
    "plus", "one", "cool", "pink", "red", "blue", "green", "black",
    "white", "gold", "city", "zone", "farm", "code", "design", "art",
    "band", "bike", "build", "cash", "dog", "engineer", "expert",
    "family", "fit", "forum", "game", "graphics", "health", "house",
    "industries", "investment", "kid", "land", "limited", "market",
    "mortgage", "museum", "music", "network", "organization", "pet",
    "phone", "photo", "pizza", "place", "plumbing", "productions",
    "properties", "recipes", "rehab", "report", "rest", "reviews",
    "school", "shopping", "social", "software", "solar", "supplies",
    "tax", "team", "tools", "training", "university", "vacations",
    "ventures", "watch", "works",
}


def harvest_javascript(urls: list[str], domain: str | None = None,
                       max_sites: int = 25,
                       max_js_per_site: int = 10, timeout: int = 12) -> dict:
    """Fetch each URL's HTML & every JS it loads; extract hosts, endpoints, secrets.

    Args:
        urls: alive URLs (from check_alive output) to deep-fetch.
        domain: OPTIONAL target-domain scope. When given, hosts found in JS
                are filtered to only those ending in `.{domain}` (or the
                apex itself). This kills the ~99% noise from JS method
                tokens like `a.id`, `Math.pow`, `foo.bar` while keeping
                every host actually on the target. Highly recommended.
        max_sites: cap how many URLs we scan (bounds total wall time).
        max_js_per_site: cap JS fetches per site (huge SPAs often 40+ files).
        timeout: per-request timeout in seconds.

    Returns dict with:
        sites_scanned, js_files_scanned, subdomains_found (list[str]),
        endpoints_found (list[str]), secrets_suspected (list[dict]),
        per_site (list[dict] with details per URL), errors.
    """
    if not urls:
        return {"sites_scanned": 0, "subdomains_found": [],
                "endpoints_found": [], "secrets_suspected": [],
                "note": "no urls given"}

    urls = urls[:max_sites]

    unique_hosts: set[str] = set()
    unique_endpoints: set[str] = set()
    secrets: list[dict] = []
    per_site: list[dict] = []
    errors: list[str] = []
    skipped_bot_walled: list[str] = []

    def _scan_site(site_url: str) -> dict | None:
        # Grab HTML page
        try:
            r = _get(site_url, timeout=timeout)
            html = r.text
        except requests.RequestException as e:
            errors.append(f"{site_url}: {type(e).__name__}")
            return None

        # Skip bot-walled / challenge pages (Vercel Security Checkpoint,
        # Cloudflare challenge, Akamai "Access Denied", etc). These return
        # 4xx/5xx with tiny HTML that has NO useful JS bundles. Wasting
        # a scan on them just adds wall time. On Tesla-scale targets
        # with 20/20 alive sites returning 403/503, this saved 100% of
        # the js_harvest stage time.
        if r.status_code >= 400 and len(html) < 5000:
            skipped_bot_walled.append(f"{site_url} ({r.status_code})")
            return None

        # Extract external JS URLs
        js_urls: set[str] = set()
        for m in re.finditer(
            r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I
        ):
            src = m.group(1)
            js_urls.add(urljoin(site_url, src))
        # modulepreload / preload as=script
        for m in re.finditer(
            r'<link[^>]+rel=["\'](?:preload|modulepreload)["\'][^>]+href=["\']([^"\']+\.js[^"\']*)["\']',
            html, re.I,
        ):
            js_urls.add(urljoin(site_url, m.group(1)))

        # Buckets scoped to this site (so per-site breakdown is honest)
        site_hosts: set[str] = set()
        site_eps: set[str] = set()
        site_secrets: list[dict] = []

        # Inline <script> blocks
        for m in re.finditer(
            r'<script(?![^>]+src=["\'])[^>]*>([\s\S]*?)</script>', html, re.I
        ):
            _extract_all(m.group(1), site_url, site_hosts,
                         site_eps, site_secrets)

        # External JS files (bounded)
        fetched = 0
        for js in js_urls:
            if fetched >= max_js_per_site:
                break
            try:
                jr = _get(js, timeout=timeout)
                if jr.status_code != 200:
                    continue
                # Cap JS file size at 2MB to avoid huge bundles timing out
                if len(jr.content) > 2_000_000:
                    continue
                _extract_all(jr.text, js, site_hosts, site_eps, site_secrets)
                fetched += 1
            except requests.RequestException:
                continue

        return {
            "url": site_url,
            "js_files_scanned": fetched,
            "hosts_found": sorted(site_hosts),
            "endpoints_found": sorted(site_eps),
            "secrets_found": site_secrets,
        }

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_scan_site, u): u for u in urls}
        for fut in as_completed(futures):
            res = fut.result()
            if not res:
                continue
            per_site.append(res)
            unique_hosts.update(res["hosts_found"])
            unique_endpoints.update(res["endpoints_found"])
            for s in res["secrets_found"]:
                secrets.append(s)

    # Drop third-party noise hosts & anything not a valid TLD-looking name
    unique_hosts = {
        h for h in unique_hosts
        if h not in NOISE_HOSTS
        and len(h.split(".")) >= 2
        and not _looks_like_file(h)
        and _has_valid_tld(h)
    }

    # If caller scoped the scan to a specific target domain, keep only
    # hosts on that domain (apex or subdomain). This is the single biggest
    # signal-to-noise win: bug bounty users care about `*.example.com`,
    # not about random method-call patterns that look like `a.id`.
    if domain:
        d = domain.lower().lstrip(".")
        unique_hosts = {
            h for h in unique_hosts
            if h == d or h.endswith("." + d)
        }

    # Drop per-session CSRF/challenge tokens that our loose
    # `generic_secret_assignment` regex catches on webmail/login pages.
    # Filter refetches each source once & keeps only stable values.
    stable_secrets, dropped_secrets = _filter_stable_secrets(
        secrets, timeout=timeout)

    return {
        "sites_scanned": len(per_site),
        "js_files_scanned": sum(p["js_files_scanned"] for p in per_site),
        "subdomains_found": sorted(unique_hosts),
        "endpoints_found": sorted(unique_endpoints)[:500],
        "secrets_suspected": stable_secrets[:50],
        "secrets_dropped_as_session_tokens": len(dropped_secrets),
        "dropped_secrets_preview": [
            {
                "kind": d["kind"],
                "value_preview": d["value_preview"],
                "found_in": d["found_in"],
                "reason": "unstable across refetch (session token)",
            }
            for d in dropped_secrets[:20]
        ],
        "sites_skipped_bot_walled": len(skipped_bot_walled),
        "skipped_details": skipped_bot_walled[:20],
        "per_site": per_site,
        "errors": errors[:20],
    }


def _looks_like_file(host: str) -> bool:
    """Reject tokens like `example.min`, `app.js`, `foo.png` that our
    hostname regex catches but are actually filenames with a TLD-suffix."""
    last = host.rsplit(".", 1)[-1].lower()
    NON_TLD = {
        "js", "css", "min", "map", "png", "jpg", "jpeg", "gif", "svg", "ico",
        "woff", "woff2", "ttf", "eot", "otf", "mp4", "webm", "mp3", "wav",
        "pdf", "zip", "tar", "gz", "br", "json", "xml", "html", "htm",
    }
    return last in NON_TLD


def _has_valid_tld(host: str) -> bool:
    """Reject tokens whose final label is not a real TLD.

    Kills ~99% of JS false positives like `a.animate`, `Math.pow`,
    `foo.prototype`, `bar.init` that our hostname regex otherwise
    matches (because `.animate` looks like a hostname label but is
    actually a JS method call)."""
    last = host.rsplit(".", 1)[-1].lower()
    # Any 2-letter alphabetic label is treated as a possible ccTLD
    # (there are ~270 ISO country codes; keeping the whitelist small
    # is not worth the false-negative risk)
    if len(last) == 2 and last.isalpha():
        return True
    return last in VALID_TLDS


def _extract_all(text: str, source: str,
                 hosts_out: set[str], eps_out: set[str],
                 secrets_out: list[dict]) -> None:
    """Run all extraction regexes on one blob of text."""
    for h in SUBDOMAIN_RE.findall(text):
        hosts_out.add(h.lower())
    for e in ENDPOINT_RE.findall(text):
        if 4 <= len(e) <= 120:
            eps_out.add(e)
    for kind, pat in SECRET_PATTERNS.items():
        for match in pat.finditer(text):
            val = match.group(1) if match.groups() else match.group(0)
            # Redact - show kind & truncated prefix so user can verify manually
            truncated = val[:12] + "..." if len(val) > 12 else val
            secrets_out.append({
                "kind": kind,
                "value_preview": truncated,
                "found_in": source,
                # raw_value kept internally for the stability filter below;
                # stripped from output so this tool never exfiltrates real
                # credentials even if downstream code logs the return dict.
                "raw_value": val,
            })


def _filter_stable_secrets(
    secrets: list[dict], timeout: int = 8
) -> tuple[list[dict], list[dict]]:
    """Refetch each source once & split into (survivors, dropped).

    The `generic_secret_assignment` regex catches webmail/login page
    CSRF challenge tokens (Roundcube / cPanel / WordPress) that change
    on every HTTP request. Those are session state, not leaks.

    For each candidate, refetch `found_in`. If raw_value is still there
    => stable => real leak => survivor. If gone or changed => session
    token => dropped. Refetch failure => keep as survivor conservatively.
    """
    if not secrets:
        return [], []

    from collections import defaultdict
    by_source: dict[str, list[dict]] = defaultdict(list)
    for s in secrets:
        by_source[s["found_in"]].append(s)

    survivors: list[dict] = []
    dropped: list[dict] = []
    for source, items in by_source.items():
        try:
            r = _get(source, timeout=timeout)
            fresh = r.text if r.status_code == 200 else None
        except Exception:
            fresh = None

        if fresh is None:
            survivors.extend(items)
            continue

        for s in items:
            if s.get("raw_value") and s["raw_value"] in fresh:
                survivors.append(s)
            else:
                dropped.append(s)

    for s in survivors + dropped:
        s.pop("raw_value", None)
    return survivors, dropped
