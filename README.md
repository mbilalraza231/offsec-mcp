# offsec-mcp

**A local-first MCP server for subdomain enumeration and passive recon.**

Wraps the popular free tools every bug bounty hunter already uses —
**subfinder**, **httpx**, **dnsx**, **nuclei** — and exposes them as
Model Context Protocol tools so any MCP client (LlamaFile, Claude Desktop,
Cursor, Cline, Continue) can drive them with a local LLM.

No cloud APIs. No API keys. No telemetry. Everything runs on your machine.

---

## Quick Start (60 seconds)

```powershell
# 1. clone + enter
git clone https://github.com/mbilalraza231/offsec-mcp.git
cd offsec-mcp

# 2. virtual env + python deps
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt

# 3. (optional but recommended) fetch the recon binaries
.\installers\install-tools.ps1      # macOS/Linux: ./installers/install-tools.sh

# 4. start the MCP server
python server.py                     # serves http://127.0.0.1:8000/sse
```

Then point any MCP client at `http://127.0.0.1:8000/sse` (SSE transport) and ask:

> *"Use the full_recon tool on example.com"*

> **It works without step 3.** Every tool has a pure-Python fallback, so you can
> skip the binaries and still enumerate + check liveness + detect takeovers.
> Only `scan_vulnerabilities` (nuclei) needs its binary.

---

## Why

Local LLMs (Llama 3, Qwen, DeepSeek via LlamaFile / Ollama) can reason about
recon results, but they can't *run* recon tools. MCP fixes that. This server
is the bridge.

## What it does

| MCP tool | Backed by | Fallback |
|----------|-----------|----------|
| `enumerate_subdomains(domain)` | subfinder -all + **11 passive APIs** (incl. **2 search-engine dorks** — DuckDuckGo + Bing — which find brand-name hosts no wordlist can reach) + **dnsx 110k-wordlist DNS brute** (finds non-web subs like git/smtp/jenkins) + **Altdns-style permutation engine** (finds compound names like staging-api, api-v2) + **httpx content-diff brute** (browser-UA, sees through Vercel/Cloudflare) + Wayback crawl | all Python, no binary needed |
| `resolve_subdomains(list)` | dnsx | dnspython |
| `check_alive(list)` | httpx (browser-UA) | Python requests |
| `scan_vulnerabilities(list)` | nuclei | none (clear error) |
| `check_takeover(list)` | pure Python CNAME fingerprint | — |
| `full_recon(domain)` | all of the above, one call | — |
| `save_results(domain, data)` | writes `./output/*.json` | — |
| `list_installed_tools()` | runtime binary detection | — |
| `list_previous_scans()` | reads `./output/` | — |

### 11 Passive Sources (all free, no keys needed)

The `enumerate_subdomains` tool queries **11 sources in parallel** using
ThreadPoolExecutor. Any single failure never blocks the pipeline.

| # | Source | Type | What it finds |
|---|--------|------|---------------|
| 1 | subfinder (binary, `-all`) | 50+ APIs merged | Massive passive coverage |
| 2 | crt.sh | Cert Transparency | All issued SSL certs |
| 3 | CertSpotter | Cert Transparency | Independent CT mirror (redundancy when crt.sh 502s) |
| 4 | **DuckDuckGo HTML dork** | **Search engine index** | **Brand-name hosts only visible in live links** (e.g. `zeenat.xinuty.com`) |
| 5 | **Bing HTML dork** | **Search engine index** | **Different crawl slice — hosts DDG/Google miss** (e.g. `2a.xinuty.com`) |
| 6 | HackerTarget | Passive DNS | Free hostsearch API |
| 7 | AlienVault OTX | Passive DNS | Historical resolutions |
| 8 | RapidDNS | Community DB | Scraped subdomains |
| 9 | Wayback Machine | URL archive | Historical archived URLs |
| 10 | ip.thc.org | Passive subdomains | The Hacker Choice DB |
| 11 | bgp.he.net | Cert Transparency | Hurricane Electric CT logs |

### Why we don't have 30 sources (honest answer)

Bug bounty tools often advertise "50+ sources" — most are dead, need API
keys, or rate-limit to 1 hit/day. When tested live, the following **all
failed** on typical recon runs (returned 401/403/404, DNS resolution
errors, or empty JSON):

| Attempted | Status |
|-----------|--------|
| Chaos Project (`dns.projectdiscovery.io`) | 401 — moved to key-required |
| Anubis (`jldc.me/anubis`) | returns HTML error page, JSON broken |
| Riddings.io | domain not resolving |
| Mnemonic PassivDNS | non-JSON response |
| DNSGrep.cn | domain not resolving |
| urlscan.io | 404/200 empty on free endpoint |
| Mojeek | domain not resolving |
| Startpage | 200 but 0 hosts (blocked) |
| PublicWWW | 200 but 0 hosts (blocked) |
| Brave Search | 429 rate-limited |
| Qwant | 403 blocked |
| Netcraft Site Report | domain not resolving |
| Searchcode | domain not resolving |
| CommonCrawl index | connection reset |
| DNSDumpster | domain not resolving |

That's 15 tried + 2 that work (DDG + Bing). Free is free — the good ones get crowded out.
If you want MORE coverage, the upgrade path is **optional API keys**:
VirusTotal, SecurityTrails, Netlas, BinaryEdge, Google Custom Search JSON.

Plus **four active stages** that run after the passive sources:

| Stage | Technique | Catches what passive misses |
|-------|-----------|-----------------------------|
| **dnsx DNS brute** | Full SecLists 110k wordlist over DNS with wildcard-IP filter | Non-web subdomains (git, smtp, jenkins, redis, internal) that don't serve HTTP |
| **Altdns permutations** | Numbered + modifier-cross-product + hyphen↔dot variants of known labels | Real-world compound names not in any wordlist: `staging-api`, `api-v2`, `dev-mail` |
| httpx content-diff brute | ~500 curated service names, resolve+probe in one pass, status+title dedup with browser UA | Live hosts absent from every index; sees through Vercel/Cloudflare bot-walls |
| Wayback link-crawl | Fetch newest archived pages of apex + www + top discovered hosts, scrape cross-links | Hosts never archived themselves but referenced from real pages |

Source attribution: every result reports which source found which subdomain.

---

## How it works behind the scenes

Three players:

```
You (LlamaFile UI)  ->  Llama-3.1 (the brain)  ->  offsec-mcp (the hands)
```

- **LlamaFile** = the chat screen.
- **Llama-3.1** = the model on your GPU. It cannot browse or run tools. It
  only *decides which tool to call* and turns the result into English.
- **offsec-mcp** = this server. It runs the real recon tools locally and
  hands back real numbers.

They talk over **SSE** — a live HTTP connection at `http://127.0.0.1:8000/sse`.

A single request, step by step:

1. On connect, the server advertises 9 tools + descriptions.
2. You type `enumerate subdomains for xinuty.com`.
3. The model does **not** guess. It emits a structured call:
   ```json
   { "tool": "enumerate_subdomains", "arguments": { "domain": "xinuty.com" } }
   ```
4. The server fires **8 passive sources in parallel** (ThreadPoolExecutor) plus
   a ~500-name httpx brute force — one shared deadline, no sequential waiting.
5. Merge → dedup → **wildcard-noise filter** → cap to 30 names (so the model's
   context window is never flooded).
6. Result goes back to the model as JSON; the model writes the summary.

### Key design choices

| Choice | Why |
|--------|-----|
| Real binaries, not model guessing | The LLM never fabricates a subdomain — every name is tool-verified |
| Parallel sources | 8 sources at once ≈ time of the slowest one, not the sum |
| `str \| list[str]` args | Some clients send lists as strings; we normalize both |
| Output capping | Thousands of results would overflow an 8B model's context |
| Binary detection + Python fallback | Works with or without `install-tools.ps1` having been run |

---

## Wildcard CDN targets (Vercel, Cloudflare)

Some targets put the **entire domain behind a wildcard CDN**. With a default
(non-browser) User-Agent these serve an identical bot-check page to every
hostname — real *or* fake — which hides real subdomains:

```
# with a bot UA (broken view):
real-hidden.com      -> 403 "Vercel Security Checkpoint"
some-random-xyz.com  -> 403 "Vercel Security Checkpoint"   (identical -> lost)
```

**This tool sends a real browser User-Agent on every HTTP probe**, so the CDN
returns the true response and real vs fake separate cleanly:

```
# with a browser UA (what offsec-mcp does):
restaurant.target.com   -> 200 "...real page..."            (kept)
some-random-xyz.com     -> 404 x-vercel-error=DEPLOYMENT_NOT_FOUND (dropped)
```

The `status + title` dedup then keeps the distinct 200 pages and discards the
uniform 404/catch-all noise. A host stays hidden **only if** all three hold:
no certificate-transparency entry, no Wayback archive, and the CDN answers
every name identically even to a browser. That residual case is a property of
the target's infrastructure, not a gap in this tool.


## Install

### 1. Python dependencies
```powershell
cd offsec-mcp
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Recon binaries (optional but recommended)
```powershell
# Windows
Set-ExecutionPolicy -Scope Process Bypass -Force
.\installers\install-tools.ps1

# Linux / macOS
bash installers/install-tools.sh
```
Binaries land in `./bin/` — project-local, does not touch system PATH.

Skip this step and the server still works — it uses Python fallbacks + crt.sh.

### 3. Run the MCP server
```powershell
python server.py
```
You'll see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### 4. Connect LlamaFile
Open LlamaFile → **Add New MCP Server** → paste:
```
http://127.0.0.1:8000/sse
```
Click **Add**. The 9 tools above appear in the tool list.

## Demo prompts

Try these in LlamaFile after connecting:

> `Use the full_recon tool on tesla.com. Do not use any other tool.`

> `Enumerate subdomains for facebook.com using the enumerate_subdomains tool`

> `Scan https://testphp.vulnweb.com for vulnerabilities using nuclei`

> `Check for subdomain takeover on example.com`

**Tip for LlamaFile --agent mode:** be specific with the tool name and say
"Do not use any other tool" to prevent the 8B model from chaining incorrectly.

## Project layout

```
offsec-mcp/
├── server.py            # MCPServer entry point, registers 9 tools, runs SSE
├── config.py            # detects binaries in ./bin/ or system PATH
├── storage.py           # saves/reads ./output/*.json
├── tools/
│   ├── enumerate.py     # 8 passive sources + httpx brute force
│   ├── resolve.py       # dnsx + dnspython
│   ├── alive.py         # httpx + requests
│   ├── vuln.py          # nuclei
│   └── takeover.py      # pure Python dangling-CNAME check
├── installers/
│   ├── install-tools.ps1
│   └── install-tools.sh
├── bin/                 # downloaded binaries (gitignored)
├── output/              # saved scans (gitignored)
├── requirements.txt
├── .gitignore
├── LICENSE              # MIT
└── README.md
```

## How the fallback logic works

Every tool file does the same thing:

1. Ask `config.find_tool("name")` if the binary is installed
2. If yes → run it via `subprocess`, parse its output
3. If no → use a pure-Python equivalent (crt.sh / dnspython / requests)
4. Return a dict with an `engine` key so the LLM knows which ran

Result: the demo never breaks, whether or not the user installed the tools.

## Ethics / scope

This is a **passive + light-active** recon toolkit for **authorized targets only**.

- Only scan domains you own or have written permission to test.
- `nuclei` and `httpx` produce real network traffic — target selection is your responsibility.
- Respect each bug bounty program's scope and rate limits.

The author accepts no liability for misuse.

## Credits

Built on:
- [Model Context Protocol](https://modelcontextprotocol.io) — Anthropic
- [MCP Python SDK v2](https://py.sdk.modelcontextprotocol.io) — Anthropic
- [ProjectDiscovery](https://projectdiscovery.io) — subfinder, httpx, dnsx, nuclei
- [SecLists](https://github.com/danielmiessler/SecLists) — subdomain wordlists
- [crt.sh](https://crt.sh) — Certificate Transparency logs
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — takeover fingerprints

## License

MIT — see [LICENSE](LICENSE).
