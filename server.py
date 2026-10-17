"""
offsec-mcp — MCP server for subdomain enumeration and recon.
Speaks Model Context Protocol over SSE so any MCP client
(LlamaFile, Claude Desktop, Cursor, Cline) can drive it.

Run:  python server.py
Serves: http://127.0.0.1:8000/sse
"""

from storage import save_results as _save, list_scans as _list
from config import detect_tools
from tools.takeover import check_takeover as _takeover
from tools.vuln import scan_vulnerabilities as _scan
from tools.alive import check_alive as _alive
from tools.resolve import resolve_subdomains as _resolve
from tools.enumerate import enumerate_subdomains as _enumerate
from tools.js_harvest import harvest_javascript as _js_harvest
from tools.sensitive import check_sensitive_files as _sensitive
from tools.waf import fingerprint as _waf_fp
from tools.archive import harvest_archived_urls as _archive_urls
from mcp.server.mcpserver import MCPServer

import json
import mcp.types as types

# --- Monkey-patch: allow string arguments (LlamaFile sends args as JSON string) ---
_original_validate = types.CallToolRequestParams.model_validate


@classmethod
def _patched_validate(cls, obj, *args, **kwargs):
    if isinstance(obj, dict) and isinstance(obj.get("arguments"), str):
        try:
            obj["arguments"] = json.loads(obj["arguments"])
        except (json.JSONDecodeError, TypeError):
            pass
    return _original_validate.__func__(cls, obj, *args, **kwargs)


types.CallToolRequestParams.model_validate = _patched_validate
# --- End patch ---


mcp = MCPServer(
    "offsec-mcp",
    instructions=(
        "Free, local-first bug-bounty recon toolkit. "
        "Subdomain enumeration combines subfinder + 11 passive APIs "
        "(incl. DuckDuckGo + Bing search-engine dorks that find brand-name "
        "hosts no wordlist can reach) with dnsx 110k-wordlist DNS brute + "
        "Altdns-style permutations + httpx content-diff active verify "
        "(browser User-Agent sees through Vercel/Cloudflare bot-walls). "
        "Full pipeline adds JS-file harvesting (hidden hosts, endpoints, "
        "secret patterns), sensitive-path probing (.git, .env, backups, "
        "actuator) with severity tags, CDN/WAF fingerprinting on every "
        "alive sub, Wayback Machine deep-URL archive harvest, subdomain "
        "takeover detection, and nuclei vulnerability scan. Falls back "
        "to pure Python when binaries are missing. Use only against "
        "domains you own or have written authorization to test."
    ),
)


def _to_list(value) -> list[str]:
    """Normalize input: accept real list, JSON list, or Python-repr list string.

    LlamaFile's MCP proxy sometimes serializes list[str] arguments as strings
    like \"['a.com', 'b.com']\" or '[\"a.com\"]'. This unifies them.
    """
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        # Try JSON first
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(v).strip() for v in parsed if str(v).strip()]
        except (json.JSONDecodeError, TypeError):
            pass
        # Try Python literal (single quotes)
        try:
            import ast
            parsed = ast.literal_eval(s)
            if isinstance(parsed, list):
                return [str(v).strip() for v in parsed if str(v).strip()]
        except (ValueError, SyntaxError):
            pass
        # Fall back: comma-separated or newline-separated raw string
        if "," in s:
            return [x.strip().strip("'\"") for x in s.split(",") if x.strip()]
        return [s]
    return []


# ---------- individual tools ----------

@mcp.tool()
def enumerate_subdomains(domain: str) -> dict:
    """Enumerate subdomains for a target domain.

    Multi-stage pipeline:
      1. subfinder -all (50+ passive sources)
      2. 8 more passive APIs in parallel (crt.sh, CertSpotter, HackerTarget,
         AlienVault OTX, RapidDNS, Wayback CDX, ip.thc.org, bgp.he.net)
      3. dnsx DNS brute force over full 110k SecLists wordlist (finds
         non-web subdomains like git/smtp/jenkins that HTTP probes miss)
      4. Altdns-style permutation of discovered labels (finds compound
         names like staging-api, api-v2, dev-mail not in any wordlist)
      5. httpx content-diff brute (browser User-Agent sees through
         Vercel/Cloudflare bot-walls) with wildcard-noise filtering
      6. Wayback link-crawl on apex + www + top discovered hosts

    Returns: {'count': int, 'subdomains': list[str], 'sources_ok': list,
              'per_source': {...}, 'truncated': bool}
    """
    return _enumerate(domain)


@mcp.tool()
def resolve_subdomains(subdomains: str | list[str]) -> dict:
    """Resolve a list of subdomains to their IP addresses using dnsx.

    Returns: {'resolved': {subdomain: [ips]}, 'failed': [subdomains]}
    """
    result = _resolve(_to_list(subdomains))
    resolved_map = result.get("resolved", {})
    result["resolved_total"] = len(resolved_map)
    # Cap resolved dict to first 30 entries in model response
    if len(resolved_map) > 30:
        result["resolved"] = dict(list(resolved_map.items())[:30])
    return result


@mcp.tool()
def check_alive(subdomains: str | list[str]) -> dict:
    """Probe subdomains over HTTP/HTTPS and keep only the live ones (httpx).

    Returns: {'alive': [{'url':..., 'status':..., 'title':...}], 'dead': [...]}
    """
    result = _alive(_to_list(subdomains))
    # Cap to avoid LLM context overflow on large target lists
    alive_list = result.get("alive", [])
    result["alive_total"] = len(alive_list)
    result["alive"] = alive_list[:30]  # Only first 30 in model response
    return result


@mcp.tool()
def scan_vulnerabilities(targets: str | list[str]) -> dict:
    """Run nuclei with the free community template set against URLs.

    Returns: {'findings': [...], 'count': int, 'severity_breakdown': {...}}
    """
    return _scan(_to_list(targets))


@mcp.tool()
def check_takeover(subdomains: str | list[str]) -> dict:
    """Detect subdomain takeover risk via dangling CNAME records.

    Returns: {'vulnerable': [{'subdomain','target','service'}], 'safe': [...]}
    """
    return _takeover(_to_list(subdomains))


@mcp.tool()
def list_installed_tools() -> dict:
    """Report which recon binaries are installed and which fallbacks are active."""
    return detect_tools()


@mcp.tool()
def save_results(domain: str, results: dict) -> dict:
    """Persist a recon result bundle to ./output/<domain>_<timestamp>.json."""
    return _save(domain, results)


@mcp.tool()
def list_previous_scans() -> dict:
    """List all previously saved scans in the ./output folder."""
    return _list()


@mcp.tool()
def js_endpoints(urls: str | list[str], domain: str = "") -> dict:
    """Deep-fetch HTML & JS files on live URLs; extract hidden hosts, endpoints,
    and possible leaked secrets.

    This is the technique top bug bounty hunters use daily. Real staging URLs,
    internal API hosts, and leaked credentials are typically NOT in certs or
    search indexes - they only live INSIDE the production JS bundle.

    Args:
        urls: list of alive URLs (from check_alive output). Cap 25 sites.
        domain: OPTIONAL target-domain scope. When provided, only hosts on
                that domain are reported (kills JS-method-name noise like
                `a.id` that would otherwise look like hostnames). Recommended.

    Returns:
        {sites_scanned, js_files_scanned, subdomains_found, endpoints_found,
         secrets_suspected (values truncated), per_site, errors}
    """
    return _js_harvest(_to_list(urls), domain=domain or None)


@mcp.tool()
def sensitive_files(urls: str | list[str]) -> dict:
    """Probe ~60 sensitive paths (.git/HEAD, .env, backup.sql, phpinfo,
    /actuator/env, wp-config.bak, swagger.json, id_rsa, ...) on live URLs.

    Any 200 with real content is a bug-bounty reportable finding. Severity is
    tagged per path (critical / high / medium / info).

    Args:
        urls: alive URLs to probe. Cap 25 sites.

    Returns:
        {urls_probed, paths_probed, total_checks, findings,
         counts_by_severity, errors}
    """
    return _sensitive(_to_list(urls))


@mcp.tool()
def waf_fingerprint(subdomains: str | list[str]) -> dict:
    """Detect CDN/WAF (Cloudflare, Vercel, Netlify, AWS CloudFront, Akamai,
    Fastly, Imperva, Sucuri, F5, Google Cloud, GitHub Pages, Azure Front Door,
    Fly.io, Render, etc.) on each subdomain from response headers.

    Useful for choosing the right bypass technique and for tagging reports
    so triagers can reproduce.

    Args:
        subdomains: hosts to probe. Cap 50.

    Returns:
        {fingerprints: [{subdomain, cdns_detected, server_header, ...}],
         summary: {Cloudflare: N, Vercel: N, ...}}
    """
    return _waf_fp(_to_list(subdomains))


@mcp.tool()
def wayback_urls(domain: str) -> dict:
    """Deep Wayback Machine harvest - return every URL archived on the target
    domain (not just hosts). Flags interesting paths (api/admin/backup/etc.)
    and sensitive extensions (.sql, .env, .bak, .zip, .pem).

    Use case: finding deprecated API endpoints, historical config leaks,
    old admin panels that were moved but never scrubbed from archive.

    Args:
        domain: apex domain (do NOT prefix `*.`).

    Returns:
        {total_archived_urls, unique_subdomains, interesting_urls,
         sample_urls, note}
    """
    return _archive_urls(domain)


# ---------- pipeline tool (money shot for the demo) ----------

@mcp.tool()
def full_recon(domain: str) -> dict:
    """One-shot bug-bounty recon pipeline. Every stage, in one call.

    Chain:
      1. enumerate_subdomains  (11 passive sources & 4 active stages)
      2. resolve_subdomains    (dnsx / dnspython fallback)
      3. check_alive           (httpx / requests, browser UA)
      4. waf_fingerprint       (CDN/WAF per alive sub)
      5. js_endpoints          (hidden hosts, endpoints, secrets from JS)
      6. sensitive_files       (.git, .env, backup, actuator, etc.)
      7. check_takeover        (dangling CNAMEs)
      8. scan_vulnerabilities  (nuclei, if installed)
      9. wayback_urls          (archived endpoints on the whole domain)

    Returns one structured report. Saved automatically to ./output/.
    """
    enum = _enumerate(domain)
    subs = enum.get("subdomains", [])[:50]
    total_found = enum.get("count", len(subs))
    if not subs:
        return {"domain": domain, "error": "no subdomains found", "enum": enum}

    # Every optional stage is wrapped in _safe() so a single flaky source
    # (Wayback 45s timeout, CertSpotter 429, mail.* self-signed cert, etc.)
    # never kills the whole 9-stage pipeline. We prefer a partial report
    # with `stage_errors` noting what failed over a total crash.
    stage_errors: list[str] = []

    def _safe(fn, name, default):
        try:
            return fn()
        except Exception as e:
            stage_errors.append(
                f"{name}:{type(e).__name__}:{str(e)[:120]}"
            )
            return default

    resolved = _safe(lambda: _resolve(subs), "resolve", {"resolved": {}})
    alive = _safe(lambda: _alive(subs), "alive", {"alive": []})
    alive_urls = [a["url"] for a in alive.get("alive", [])]

    # Stages 4-9 (waf, js, sensitive, wayback, takeover, nuclei) are all
    # independent - they only need `subs` or `alive_urls` as input. Run
    # them concurrently to cut wall-time roughly in half (previously
    # sequential; ~4min -> ~2min on typical 8-sub target).
    from concurrent.futures import ThreadPoolExecutor
    waf_default = {"fingerprints": [], "summary": {}}
    js_default = {"sites_scanned": 0, "subdomains_found": [],
                  "endpoints_found": [], "secrets_suspected": []}
    sens_default = {"findings": [], "counts_by_severity": {}}
    wb_default = {"total_archived_urls": 0, "interesting_urls": []}
    tk_default = {"vulnerable": []}
    nuc_default = {"findings": [], "count": 0}

    def _t_waf(): return _safe(lambda: _waf_fp(subs), "waf_fingerprint", waf_default)

    def _t_js(): return _safe(
        lambda: _js_harvest(
            alive_urls, domain=domain) if alive_urls else js_default,
        "js_endpoints", js_default)

    def _t_sens(): return _safe(
        lambda: _sensitive(alive_urls) if alive_urls else sens_default,
        "sensitive_files", sens_default)

    def _t_wb(): return _safe(lambda: _archive_urls(domain), "wayback_urls", wb_default)
    def _t_tk(): return _safe(lambda: _takeover(subs), "takeover", tk_default)

    def _t_nuc(): return _safe(
        lambda: _scan(alive_urls[:100]) if alive_urls else nuc_default,
        "nuclei", nuc_default)

    with ThreadPoolExecutor(max_workers=6) as _pool:
        _futs = {
            "waf": _pool.submit(_t_waf),
            "js": _pool.submit(_t_js),
            "sensitive": _pool.submit(_t_sens),
            "wayback": _pool.submit(_t_wb),
            "takeover": _pool.submit(_t_tk),
            "nuclei": _pool.submit(_t_nuc),
        }
        waf = _futs["waf"].result()
        js = _futs["js"].result()
        sensitive = _futs["sensitive"].result()
        archive = _futs["wayback"].result()
        takeover = _futs["takeover"].result()
        vulns = _futs["nuclei"].result()

    # Binary availability report - if recon results are thin, users can
    # immediately see whether they need to run installers/install-tools.ps1
    from config import find_tool as _find_tool
    missing_binaries = [b for b in ("subfinder", "httpx", "dnsx", "nuclei")
                        if not _find_tool(b)]

    report = {
        "domain": domain,
        "subdomains_found": total_found,
        "subdomains_probed": len(subs),
        "subdomains_resolved": len(resolved.get("resolved", {})),
        "subdomains_alive": len(alive.get("alive", [])),
        "wildcard_catchall_filtered": alive.get("wildcard_catchall_count", 0),
        "confidence_summary": enum.get("confidence_summary", {}),
        "sources_used": enum.get("per_source", {}),
        "sources_failed": enum.get("sources_failed", []),
        "alive_details": alive.get("alive", [])[:10],
        "waf_summary": waf.get("summary", {}),
        "waf_details": waf.get("fingerprints", [])[:15],
        "js_harvest": {
            "sites_scanned": js.get("sites_scanned", 0),
            "js_files_scanned": js.get("js_files_scanned", 0),
            "extra_subdomains_found": js.get("subdomains_found", [])[:30],
            "endpoints_found": js.get("endpoints_found", [])[:60],
            "secrets_suspected": js.get("secrets_suspected", [])[:20],
        },
        "sensitive_findings": {
            "total_checks": sensitive.get("total_checks", 0),
            "counts_by_severity": sensitive.get("counts_by_severity", {}),
            "top_findings": sensitive.get("findings", [])[:30],
        },
        "wayback_summary": {
            "total_archived_urls": archive.get("total_archived_urls", 0),
            "interesting_count": archive.get("interesting_count", 0),
            "interesting_sample": archive.get("interesting_urls", [])[:30],
            "error": archive.get("error"),
        },
        "takeover_risks": takeover.get("vulnerable", []),
        "vulnerabilities": vulns,
        "missing_binaries": missing_binaries,
        "stage_errors": stage_errors,
        "note": (
            "If `stage_errors` is non-empty, some optional stages failed "
            "but the pipeline continued. Every stage is wrapped in a "
            "try/except so one flaky source never kills the whole run."
        ) if stage_errors else None,
    }
    # Drop None note field to keep response compact when nothing failed
    if report.get("note") is None:
        report.pop("note", None)
    _save(domain, report)
    return report


if __name__ == "__main__":
    import uvicorn
    from starlette.middleware.cors import CORSMiddleware

    # Build the SSE ASGI app + CORS
    app = mcp.sse_app(host="127.0.0.1")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    print("[*] offsec-mcp SSE server starting on http://127.0.0.1:8000/sse")
    uvicorn.run(app, host="127.0.0.1", port=8000)
