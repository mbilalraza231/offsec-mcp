"""
tools/sensitive.py - probe common sensitive file paths on live subdomains.

Exposure of `.git/HEAD`, `.env`, `backup.zip`, `phpinfo.php`, `/actuator/env`,
`wp-config.php.bak`, etc. is directly reportable in every major bug bounty
program (HackerOne/Bugcrowd) - severity ranges from Information Disclosure
(medium) to full RCE via private key leak (critical).

Pure Python & HTTP GETs. No API key, no binary. Each response classified
by severity so downstream tooling can prioritize.
"""

from concurrent.futures import ThreadPoolExecutor

import requests

from tools._http import DEFAULT_HEADERS as HEADERS, strict_get as _get
# 40+ paths that appear in real CTFs / CVEs / disclosed bugs
SENSITIVE_PATHS = [
    # VCS & local history
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.gitlab-ci.yml",
    "/.svn/entries", "/.hg/hgrc", "/.bzr/README",
    # Env files & secrets
    "/.env", "/.env.bak", "/.env.local", "/.env.production", "/.env.staging",
    "/.aws/credentials", "/.npmrc", "/pipfile.lock",
    # Backups & database dumps
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/database.sql", "/dump.sql", "/data.sql.gz", "/db.sqlite",
    "/latest.dump", "/snapshot.tar.gz",
    # OS metadata leaks
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    # Web-server config
    "/web.config", "/nginx.conf", "/apache2.conf", "/httpd.conf",
    "/configuration.ini", "/config.json", "/config.yml", "/config.yaml",
    "/config.inc.php", "/config.php.bak", "/config.php~",
    # PHP info probes
    "/phpinfo.php", "/info.php", "/test.php", "/php.php", "/pi.php",
    # Server-status / telemetry
    "/server-status", "/server-info",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
    # Laravel
    "/telescope", "/horizon", "/_debugbar/open",
    # Admin panels & CMS
    "/admin", "/administrator", "/admin/login", "/admin panel",
    "/phpmyadmin/", "/adminer.php", "/manager/html",
    "/wp-login.php", "/wp-admin/", "/wp-config.php.bak", "/xmlrpc.php",
    "/wp-content/uploads/dup-installer/",
    # Console / debug
    "/debug", "/__debug__", "/_next/static", "/console",
    # Public API schemas
    "/swagger.json", "/openapi.json", "/api-docs", "/graphql",
    # Crypto material
    "/id_rsa", "/.ssh/id_rsa", "/private.pem", "/server.key",
    # Cross-domain policies (sometimes reveal internal hosts)
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Crawl hints (sometimes list hidden paths)
    "/robots.txt", "/sitemap.xml",
    # Common credential files
    "/credentials", "/credentials.json", "/secrets.yaml",
    "/password.txt", "/secret.txt", "/config.bak",
]

# Signals that a "200 OK" response is actually a wildcard page (soft-404).
# If the body matches any of these, we downweight or skip.
WILDCARD_MARKERS = [
    b"not found", b"404", b"page not found", b"the page you requested",
    b"deployment_not_found", b"<title>error", b"come back soon",
    b"site under maintenance",
]

SEVERITY_MAP = {
    # Critical - direct RCE / full source / credential leak
    "/.git/HEAD": "critical", "/.git/config": "critical",
    "/.env": "critical", "/.env.bak": "critical",
    "/.env.production": "critical", "/.env.local": "critical",
    "/.env.staging": "critical", "/.aws/credentials": "critical",
    "/id_rsa": "critical", "/.ssh/id_rsa": "critical",
    "/private.pem": "critical", "/server.key": "critical",
    "/backup.sql": "critical", "/db.sql": "critical",
    "/database.sql": "critical", "/dump.sql": "critical",
    "/config.php.bak": "critical", "/config.inc.php": "critical",
    "/wp-config.php.bak": "critical", "/credentials": "critical",
    "/credentials.json": "critical", "/secrets.yaml": "critical",
    "/backup.zip": "critical", "/backup.tar.gz": "critical",
    # High - info disclosure that materially helps attacker
    "/.gitignore": "high", "/.hg/hgrc": "high", "/.svn/entries": "high",
    "/server-status": "high", "/server-info": "high",
    "/phpinfo.php": "high", "/info.php": "high", "/test.php": "high",
    "/web.config": "high", "/nginx.conf": "high",
    "/actuator/env": "high", "/actuator/beans": "high",
    "/actuator/mappings": "high", "/actuator/configprops": "high",
    "/telescope": "high", "/horizon": "high",
    "/adminer.php": "high", "/manager/html": "high",
    "/swagger.json": "high", "/openapi.json": "high", "/graphql": "high",
    # Medium - admin surface that shouldn't be public
    "/.DS_Store": "medium", "/Thumbs.db": "medium",
    "/xmlrpc.php": "medium", "/wp-login.php": "medium",
    "/wp-admin/": "medium", "/administrator": "medium",
    "/admin": "medium", "/admin/login": "medium",
    "/phpmyadmin/": "medium", "/debug": "medium",
    "/__debug__": "medium", "/console": "medium", "/actuator": "medium",
    "/actuator/health": "medium", "/api-docs": "medium",
    # Informational - useful for fingerprinting only
    "/robots.txt": "info", "/sitemap.xml": "info", "/crossdomain.xml": "info",
    "/clientaccesspolicy.xml": "info", "/.gitlab-ci.yml": "info",
}


def check_sensitive_files(urls: list[str], max_urls: int = 25,
                          timeout: int = 8, max_workers: int = 12) -> dict:
    """Probe every SENSITIVE_PATH on every URL; report hits with severity.

    Args:
        urls: alive URLs (from check_alive) - pass the URL as returned by
              httpx (e.g. `https://www.example.com`), no trailing slash needed.
        max_urls: cap sites probed so a domain with 200 subs doesn't
                  produce 8000 requests.
        timeout: per-request timeout.
        max_workers: parallel probes.

    Returns:
        {
            "urls_probed": int,
            "paths_probed": int,
            "total_checks": int,
            "findings": [
                {"url","path","status","length","content_type","severity",
                 "preview"}, ...
            ],
            "counts_by_severity": {"critical":N,"high":N,...},
            "soft404_filtered": int,   # findings dropped as SPA fallback
            "errors": [str,...],
        }
    """
    if not urls:
        return {"findings": [], "note": "no urls given"}

    urls = [u.rstrip("/") for u in urls[:max_urls]]
    findings: list[dict] = []
    errors: list[str] = []
    soft404_dropped = 0

    # ---- Baseline soft-404 detection per base URL ----
    # SPAs (Next.js, Angular, Vue) & some WAFs serve the SAME fallback page
    # for ANY unknown path with status 200. Without this filter, auth.tesla.com
    # returned "critical" hits for /dump.sql, /test.php, /latest.dump etc. -
    # all showing the login HTML, none actually leaked.
    #
    # Method: fetch a random 40-char nonce path per base URL. If it returns
    # 200 with non-trivial body, we assume any subsequent 200 with matching
    # length AND matching first 200 bytes is the same soft-404 SPA fallback.
    import random as _random
    import string as _string

    def _get_baseline(base_url: str) -> tuple[int, bytes] | None:
        nonce = "".join(
            _random.choices(_string.ascii_lowercase + _string.digits, k=40))
        url = f"{base_url}/offsec-baseline-{nonce}"
        try:
            r = _get(url, timeout=timeout)
        except requests.RequestException:
            return None
        if r.status_code != 200 or len(r.content) < 5:
            return None
        return (len(r.content), r.content[:200])

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        baselines: dict[str, tuple[int, bytes] | None] = dict(
            zip(urls, pool.map(_get_baseline, urls))
        )

    def _probe(task):
        base_url, path = task
        target = base_url + path
        try:
            r = _get(target, timeout=timeout)
        except requests.RequestException as e:
            errors.append(f"{target}: {type(e).__name__}")
            return None
        # Only 2xx/3xx count as reachable
        if r.status_code >= 400:
            return None
        # Body must be non-trivial to count as real file
        if len(r.content) < 5:
            return None
        # Soft-404 / wildcard detection: if body clearly says "not found",
        # skip. Otherwise wildcard DNS would inflate every path into a hit.
        low = r.content[:2000].lower()
        if any(m in low for m in WILDCARD_MARKERS):
            return None
        # Baseline soft-404: if this response matches the SPA fallback page
        # we detected for this base URL, discard as false positive.
        baseline = baselines.get(base_url)
        if baseline:
            blen, bpre = baseline
            rlym = len(r.content)
            # Same length within 5% AND same first-200 signature = fallback
            if abs(rlym - blen) <= max(20, blen * 0.05) \
                    and r.content[:200] == bpre:
                return "SOFT404_BASELINE"
        preview = r.text[:250].replace("\n", " ").replace("\r", " ").strip()
        sev = SEVERITY_MAP.get(path, "info")
        return {
            "url": target,
            "path": path,
            "status": r.status_code,
            "length": len(r.content),
            "content_type": r.headers.get("Content-Type", "")[:80],
            "severity": sev,
            "preview": preview,
            "tls_verified": getattr(r, "_tls_verified", True),
        }

    tasks = [(u, p) for u in urls for p in SENSITIVE_PATHS]

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for res in pool.map(_probe, tasks):
            if res == "SOFT404_BASELINE":
                soft404_dropped += 1
            elif res:
                findings.append(res)

    counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "urls_probed": len(urls),
        "paths_probed": len(SENSITIVE_PATHS),
        "total_checks": len(tasks),
        "findings": findings,
        "counts_by_severity": counts,
        "soft404_filtered": soft404_dropped,
        "errors": errors[:20],
    }
