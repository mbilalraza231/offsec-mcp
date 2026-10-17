"""
tools/takeover.py — subdomain takeover detection via dangling CNAMEs.

Pure Python. No external binary needed.
Checks CNAME targets against a curated list of known takeover-prone services.
Parallel execution (20 workers) — fast even on 1000+ subdomains.
"""

import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

# service fingerprint -> friendly name
# reference: https://github.com/EdOverflow/can-i-take-over-xyz
TAKEOVER_FINGERPRINTS = {
    "github.io":              "GitHub Pages",
    "gitlab.io":              "GitLab Pages",
    "bitbucket.io":           "Bitbucket",
    "herokuapp.com":          "Heroku",
    "netlify.app":            "Netlify",
    "azurewebsites.net":      "Azure App Service",
    "cloudapp.net":           "Azure Cloud Service",
    "blob.core.windows.net":  "Azure Blob Storage",
    "s3.amazonaws.com":       "AWS S3",
    "s3-website":             "AWS S3 Website",
    "fastly.net":             "Fastly",
    "unbouncepages.com":      "Unbounce",
    "shopify.com":            "Shopify",
    "tumblr.com":             "Tumblr",
    "wordpress.com":          "WordPress.com",
    "readme.io":              "ReadMe",
    "surge.sh":               "Surge.sh",
    "webflow.io":             "Webflow",
    "worksites.net":          "SimpleBooklet",
    "zendesk.com":            "Zendesk",
    "statuspage.io":          "Statuspage",
    "intercom.io":            "Intercom",
    "cargocollective.com":    "Cargo",
    "tictail.com":            "Tictail",
    "e-monsite.com":          "E-Monsite",
    "create.re":              "CreateRe",
}


def check_takeover(subdomains: list[str]) -> dict:
    vulnerable, safe, unresolved = [], [], []

    def _check_one(sub: str):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(sub, "CNAME")
            target = str(answers[0].target).lower().rstrip(".")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return (sub, None, "unresolved")
        except Exception:
            return (sub, None, "unresolved")

        matched = next(
            (svc for fp, svc in TAKEOVER_FINGERPRINTS.items() if fp in target),
            None,
        )
        if matched:
            return (sub, target, matched)
        return (sub, target, "safe")

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_check_one, s): s for s in subdomains}
        for fut in as_completed(futures):
            sub, target, status = fut.result()
            if status == "unresolved":
                unresolved.append(sub)
            elif status == "safe":
                safe.append(sub)
            else:
                vulnerable.append({
                    "subdomain": sub,
                    "cname_target": target,
                    "service": status,
                    "note": (
                        f"Points to {status}. Verify upstream is unclaimed "
                        "before reporting (see https://github.com/EdOverflow/"
                        "can-i-take-over-xyz)."
                    ),
                })

    return {
        "vulnerable": vulnerable,
        "safe": safe,
        "unresolved": unresolved,
        "engine": "python-dnspython-parallel",
    }
