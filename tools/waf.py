"""
tools/waf.py - identify WAF/CDN/hosting providers on live subdomains from
response headers alone (no active fingerprinting, no rate-limit risk).

Why this matters: knowing what stands in front of a target changes strategy
completely. Cloudflare challenges block naive nuclei runs. Vercel serves
403 checkpoints to non-browser UAs. Akamai hides behind `MPF-*` cookies.
Bug bounty reports frequently require tagging the observed CDN so triagers
can reproduce.

Pure Python, free, no keys, no binaries.
"""

from concurrent.futures import ThreadPoolExecutor

from tools._http import strict_get, strict_head

# Header-signature map. Each entry is (friendly-name, [header-tokens])
# where any single token match counts as a positive detection. Tokens are
# lowercased and compared against `key:value` combined strings.
CDN_SIGNATURES = [
    ("Cloudflare", [
        "server:cloudflare", "cf-ray", "cf-cache-status",
        "cf-request-id", "cf-visitor",
    ]),
    ("Vercel", [
        "server:vercel", "x-vercel-id", "x-vercel-cache",
    ]),
    ("Netlify", [
        "server:netlify", "x-nf-request-id", "x-nf-invocation",
    ]),
    ("AWS CloudFront", [
        "via:1.1 varnish", "x-amz-cf-id", "x-cache:miss from cloudfront",
        "x-cache:hit from cloudfront", "server:cloudfront",
    ]),
    ("Fastly", [
        "x-fastly-request-id", "x-cache-hits", "x-served-by:cache-",
        "x-timer:S",
    ]),
    ("Akamai", [
        "server:akamai", "server:akamaighost", "x-akamai-transformed",
        "mpm-account", "mpm-host",
    ]),
    ("Google Cloud (GCP)", [
        "server:google", "x-gcp-la2", "x-goog-backend-info",
        "via:1.1 google",
    ]),
    ("GitHub Pages", [
        "server:github.com", "x-github-request-id",
    ]),
    ("Firebase Hosting", [
        "server:firebase", "x-firebase-project-id",
    ]),
    ("Imperva / Incapsula", [
        "x-iinfo", "server:incapsula",
    ]),
    ("Sucuri", [
        "x-sucuri-id", "x-sucuri-cache", "server:sucuri/cloudproxy",
    ]),
    ("F5 BIG-IP", [
        "x-waf-nitshield", "bigipserver",
    ]),
    ("Barracuda", [
        "barrier:", "barracuda",
    ]),
    ("Bunny CDN", [
        "server:bunny", "bunnycdn",
    ]),
    ("KeyCDN", [
        "server:keycdn", "x-cache:KEYCDN",
    ]),
    ("Cloudflare Pages", [
        "cf-cache-status", "server:cloudflare",
    ]),
    ("Render.com", [
        "server:render",
    ]),
    ("Fly.io", [
        "server:fly", "x-fly-request-id",
    ]),
    ("Heroku", [
        "request-id:ve", "server:heroku",
    ]),
    ("Azure Front Door", [
        "x-azure-ref", "x-fd-int-health", "azurecdn",
    ]),
    ("Wordfence (WP)", [
        "x-wordfence", "wordfence",
    ]),
]

# Response headers that hint at application stack (bonus context, not CDN).
APP_STACK_HEADERS = [
    "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache",
    "x-server", "x-page-speed", "x-Mod-Pagespeed",
]


def fingerprint(subdomains: list[str], max_subs: int = 50,
                timeout: int = 8) -> dict:
    """Probe each subdomain once and classify CDN/WAF from response headers.

    Args:
        subdomains: hosts (or URLs) to fingerprint.
        max_subs: cap how many we hit (bounds wall time; recon runs on
                  large targets should not fan out unbounded).
        timeout: per-request timeout in seconds.

    Returns:
        {
            "fingerprints": [
                {"subdomain", "url", "status", "cdns_detected": [...],
                 "server_header", "powered_by", "has_cors_wildcard",
                 "tls_verified", "interesting_headers": {...}}
            ],
            "summary": {"Cloudflare": N, "Vercel": N, ...},  # count per CDN
            "errors": [...],
        }
    """
    if not subdomains:
        return {"fingerprints": [], "note": "no subdomains given"}

    subs = subdomains[:max_subs]
    results: list[dict] = []
    errors: list[str] = []

    def _fp(sub: str) -> dict | None:
        # Prefer HEAD; fall back to GET if 405 or block
        url = sub if sub.startswith(
            ("http://", "https://")) else f"https://{sub}"
        r = None
        try:
            r = strict_head(url, timeout=timeout, allow_redirects=True)
            if r.status_code in (403, 405, 501):
                r = strict_get(url, timeout=timeout, stream=True)
        except Exception as e:
            try:
                r = strict_get(url, timeout=timeout, stream=True)
            except Exception as e2:
                errors.append(
                    f"{sub}: HEAD={type(e).__name__} GET={type(e2).__name__}")
                return None

        headers = {k.lower(): str(v) for k, v in r.headers.items()}
        # Build combined blob to compare each signature token against
        blob = " ".join(f"{k}:{v}".lower() for k, v in headers.items())

        cdns = []
        for name, tokens in CDN_SIGNATURES:
            for tok in tokens:
                if tok.lower() in blob:
                    cdns.append(name)
                    break

        # Collect app-stack info (server, x-powered-by, etc.)
        stack = {}
        for h in APP_STACK_HEADERS:
            if h.lower() in headers:
                stack[h.lower()] = headers[h.lower()][:100]

        # CORS wildcard = common misconfig worth flagging
        acao = headers.get("access-control-allow-origin", "")
        has_cors_star = acao.strip() == "*"

        return {
            "subdomain": sub,
            "url": getattr(r, "url", url),
            "status": r.status_code,
            "cdns_detected": cdns,
            "server_header": headers.get("server"),
            "powered_by": headers.get("x-powered-by"),
            "has_cors_wildcard": has_cors_star,
            "tls_verified": getattr(r, "_tls_verified", True),
            "stack_headers": stack,
        }

    with ThreadPoolExecutor(max_workers=15) as pool:
        for res in pool.map(_fp, subs):
            if res:
                results.append(res)

    summary: dict[str, int] = {}
    for r in results:
        for c in r["cdns_detected"]:
            summary[c] = summary.get(c, 0) + 1

    return {
        "fingerprinted": len(results),
        "fingerprints": results,
        "summary": summary,
        "errors": errors[:20],
    }
