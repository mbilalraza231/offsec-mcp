"""
tools/resolve.py — DNS A/CNAME resolution.

Primary: dnsx
Fallback: dnspython (pure Python)
"""

import subprocess

import dns.resolver

from config import find_tool

TIMEOUT = 20


def resolve_subdomains(subdomains: list[str]) -> dict:
    if not subdomains:
        return {"resolved": {}, "failed": []}

    dnsx = find_tool("dnsx")
    if dnsx:
        try:
            payload = "\n".join(subdomains).encode()
            out = subprocess.check_output(
                [dnsx, "-silent", "-a", "-cname"],
                input=payload, stderr=subprocess.DEVNULL, timeout=TIMEOUT,
            ).decode(errors="ignore")
            resolved, failed = _parse_dnsx(out, subdomains)
            return {"resolved": resolved, "failed": failed, "engine": "dnsx"}
        except Exception:
            pass  # fall through to Python resolver

    return _python_resolve(subdomains)


def _parse_dnsx(output: str, original: list[str]) -> tuple[dict, list]:
    resolved: dict[str, list[str]] = {}
    seen: set[str] = set()
    for line in output.splitlines():
        parts = [p.strip() for p in line.split() if p.strip()]
        if not parts:
            continue
        host = parts[0].lower()
        seen.add(host)
        resolved.setdefault(host, []).extend(parts[1:])
    failed = [s for s in original if s.lower() not in seen]
    return resolved, failed


def _python_resolve(subdomains: list[str]) -> dict:
    """Parallel Python fallback for DNS resolution when dnsx not available."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    resolved: dict[str, list[str]] = {}
    failed: list[str] = []

    def _resolve_one(sub):
        r = dns.resolver.Resolver()
        r.timeout = 5
        r.lifetime = 5
        try:
            return (sub, sorted({a.address for a in r.resolve(sub, "A")}))
        except Exception:
            return (sub, None)

    with ThreadPoolExecutor(max_workers=20) as pool:
        for sub, ips in pool.map(_resolve_one, subdomains):
            if ips:
                resolved[sub] = ips
            else:
                failed.append(sub)

    return {"resolved": resolved, "failed": failed, "engine": "python-dnspython-parallel"}
