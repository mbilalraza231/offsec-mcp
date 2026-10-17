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
        "Free, local-first subdomain enumeration and recon toolkit. "
        "Combines 8 passive sources (subfinder, crt.sh, AlienVault OTX, "
        "Wayback, and more) with an active httpx brute-force pass that uses a "
        "real browser User-Agent to see through Vercel/Cloudflare bot-walls. "
        "Falls back to crt.sh / pure Python when binaries are missing. "
        "Use only against domains you own or have written authorization to test."
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

    Runs 8 passive intelligence sources in parallel, then an active httpx
    brute-force pass (curated service wordlist + wildcard-noise filtering),
    then a Wayback link-crawl. Uses a real browser User-Agent so hosts behind
    Vercel/Cloudflare bot-walls are still discovered.

    Args:
        domain: root domain, e.g. 'example.com' (no protocol, no www)

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


# ---------- pipeline tool (money shot for the demo) ----------

@mcp.tool()
def full_recon(domain: str) -> dict:
    """One-shot recon pipeline: enumerate -> resolve -> alive -> takeover -> nuclei.

    This is the flagship tool for demos. Give it a domain, get a structured
    recon report back in one call.
    """
    enum = _enumerate(domain)
    # Use the first 50 subs for pipeline (alive/resolve/takeover) to stay time-bounded
    subs = enum.get("subdomains", [])[:50]
    total_found = enum.get("count", len(subs))  # Actual total from all sources
    if not subs:
        return {"domain": domain, "error": "no subdomains found", "enum": enum}

    resolved = _resolve(subs)
    alive = _alive(subs)
    takeover = _takeover(subs)

    urls = [a["url"] for a in alive.get("alive", [])]
    # Cap nuclei at first 100 URLs to keep pipeline time-bounded
    vulns = _scan(urls[:100]) if urls else {"findings": [], "count": 0}

    report = {
        "domain": domain,
        "subdomains_found": total_found,
        "subdomains_probed": len(subs),
        "subdomains_resolved": len(resolved.get("resolved", {})),
        "subdomains_alive": len(alive.get("alive", [])),
        "wildcard_catchall_filtered": alive.get("wildcard_catchall_count", 0),
        "takeover_risks": takeover.get("vulnerable", []),
        "vulnerabilities": vulns,
        "sources_used": enum.get("per_source", {}),
        "alive_details": alive.get("alive", [])[:10],
    }
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
