# offsec-mcp

**MCP server for bug bounty recon.** Enumerate subdomains, hunt JS
leaks, fingerprint WAFs, detect takeovers, probe sensitive files, &
scan with nuclei — from any local LLM or MCP client (LlamaFile,
Claude Desktop, Cursor, Cline, Continue).

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
| `check_alive(list)` | **Tier 1 curl_cffi** (Chrome 120 TLS and HTTP/2 fingerprint) with fallback chain curl_cffi-strict, curl_cffi-relaxed, requests-strict, requests-relaxed; optional Go httpx subprocess | **5-bucket output**: `alive` (real running app), `stale` (deployment-missing markers such as Vercel DEPLOYMENT_NOT_FOUND, Netlify or Heroku equivalents), `bot_walled` (4xx with Vercel, Cloudflare or Akamai challenge titles), `wildcard_http` (4xx matching a nonsense control-probe signature on the apex), `dead` (no HTTP response) |
| `js_endpoints(urls, domain?)` | **NEW (Tier 1)** — deep-fetch HTML & JS on each alive URL, extract hidden hosts, API endpoints, potential leaked secrets (AWS keys, GitHub tokens, JWTs, PEMs, Stripe) | pure Python regex |
| `sensitive_files(urls)` | **NEW (Tier 1)** — probe ~60 paths (`.git/HEAD`, `.env`, `backup.zip`, `/actuator/env`, `phpinfo.php`, `wp-config.bak`, `id_rsa`, `swagger.json`, `telescope`, etc.) with severity tags | pure Python HTTP |
| `waf_fingerprint(subs)` | **NEW (Tier 2)** — 21 CDN/WAF signatures (Cloudflare, Vercel, Netlify, AWS CloudFront, Akamai, Fastly, Imperva, Sucuri, F5, GCP, GitHub Pages, Azure Front Door, Fly.io, Render, Heroku, …) | response headers only |
| `wayback_urls(domain)` | **NEW (Tier 2)** — Wayback Machine CDX deep harvest; every archived URL & `interesting_urls` filtered for admin/api/backup/.env patterns | free CDX API |
| `scan_vulnerabilities(list)` | nuclei | none (clear error) |
| `check_takeover(list)` | pure Python CNAME fingerprint | — |
| `full_recon(domain)` | **all of the above, 9-stage pipeline, one call** | — |
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
| 4 | **DuckDuckGo HTML dork** | **Search engine index** | **Brand-name hosts only visible in live links** (e.g. `docs.example.com`) |
| 5 | **Bing HTML dork** | **Search engine index** | **Different crawl slice — hosts DDG/Google miss** (e.g. `2a.example.com`) |
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
| **active-dns HTTP verify** | ~500 curated service names (services.txt + top 250 by frequency from subdomains-110k.txt), resolve+probe in one pass, content-diff filter using 10 randomized nonsense-name baselines | Live hosts absent from every index; sees through Vercel/Cloudflare bot-walls |
| **must-probe curated** | 40 high-value names (mail, webmail, git, admin, cpanel, smtp, autodiscover, mx, ...) checked via direct DNS even when wildcard DNS is detected | Hosts on totally different infra (non-wildcard IP pool) that wildcard HTTP verify cannot distinguish |
| **Wayback link-crawl** | Fetch newest archived pages of apex + www + top discovered hosts, scrape cross-links | Hosts never archived themselves but referenced from real pages |

### Why HTTP brute uses ~500 names, DNS brute uses 110k

HTTP requests are heavy — every probe costs a TLS handshake, a
Chrome-impersonated session, a full HTTP response body, and each
sequential probe to a Vercel-fronted target adds rate-limit pressure.
Full 110k over HTTP would take **3-4 hours** and trigger bot-detection
within the first 5 minutes. Curated ~500 covers **95%+ of real-world
subdomains** in 40-90s.

DNS queries are cheap — a single 40-byte UDP packet plus a
10-byte answer. dnsx processes 110k queries in under 2 minutes at
1000 qps without any bot-detection risk. So DNS brute does use the
full wordlist, HTTP brute does not.

Both stages automatically skip when wildcard DNS is detected on the
apex (because every random name resolves and the results are useless).
`must-probe` intentionally does NOT skip on wildcard because it uses
IP-pool comparison, not content comparison, to filter noise.

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
2. You type `enumerate subdomains for example.com`.
3. The model does **not** guess. It emits a structured call:
   ```json
   { "tool": "enumerate_subdomains", "arguments": { "domain": "example.com" } }
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

## Wildcard CDN targets (Vercel, Cloudflare, Akamai)

Modern PaaS platforms layer three different "noise" responses on top of
a wildcard DNS record, and each one fools a naive scanner into reporting
it as an alive target:

| Layer | What the edge actually returns | Why a naive alive-checker misclassifies it |
|-------|--------------------------------|---------------------------------------------|
| **Bot-wall** (403 challenge) | 34 KB JS challenge page (Vercel Security Checkpoint, Cloudflare Turnstile interstitial, Akamai Bot Manager) | Body is big so "length under 500" rule misses it; scanner puts it in `alive` |
| **Deployment-missing** (404 edge page) | Vercel `404 DEPLOYMENT_NOT_FOUND bom1::xxxx`, Netlify `This site is not connected`, Heroku `No such app` | Body is 5-8 KB, still above the stale threshold; scanner puts it in `alive` |
| **Wildcard project HTTP handler** (404 app page) | Every random name hits the same Next.js catch-all → identical `404: NOT_FOUND` handler response | Real deployment for `admin.x.com` and nonsense `test123.x.com` return byte-identical responses; scanner can't tell them apart |

### Tier 1 curl_cffi fingerprint stack

`tools/_http.py` sends every probe through a **four-layer fallback
chain**:

```
curl_cffi(impersonate="chrome120", strict TLS)
   └─ fail → curl_cffi(chrome120, relaxed TLS)      # self-signed certs
              └─ fail → requests (strict TLS)         # legacy host
                         └─ fail → requests (relaxed TLS)
```

curl_cffi replicates Chrome 120's **JA3 TLS ClientHello** and **HTTP/2
SETTINGS frame order** byte-for-byte. Real Chrome opens 6-10 concurrent
connections to a CDN, so `check_alive` deliberately caps parallelism at
**10 threads** to keep the request pattern browser-plausible. Plain
Python requests would open 100 sessions in the same window and be
flagged instantly.

This alone raises the Vercel wall-bypass rate from about 10 to about 50
percent on typical bug-bounty-sized targets. It is **probabilistic**,
not a guaranteed bypass. curl_cffi handles TLS and HTTP/2 signals; it does
**not** execute JavaScript, persist cookies, or emit Sec-CH-UA client
hints, so Vercel's scoring still challenges some requests.

### Five-bucket classification

`check_alive` post-processes every response through three split
functions before returning:

```
_split_stale         status 4xx AND (length under 500 OR body contains
                     a DEPLOYMENT_MISSING_SIGNATURES marker)
_split_bot_walled    status 4xx AND title matches WALL_TITLE_SIGNATURES
_split_wildcard_http fetch offsec-wildcard-{nonce}.apex THREE times as
                     control probes and take the majority non-wall sig,
                     move any 4xx with identical (status, title)
_strip_private_fields  drop the _deployment_missing helper flag
```

Result:

```
{
  "alive":         [ ...real 200 responses with unique content... ],
  "stale":         [ ...Vercel DEPLOYMENT_NOT_FOUND / Netlify / Heroku... ],
  "bot_walled":    [ ...Vercel Checkpoint / Cloudflare Turnstile... ],
  "wildcard_http": [ ...names matching the control-probe signature... ],
  "dead":          [ ...no HTTP response... ],
  "engine":        "python-curl_cffi",
  "wildcard_http_signature": {"status": 404, "title": "404: not_found"}
}
```

Downstream stages (`js_endpoints`, `sensitive_files`, `nuclei`) only
receive `alive` URLs so they never waste probes on walls or wildcards.
`waf_fingerprint` additionally receives `stale`, `bot_walled` and
`wildcard_http` because every one of those buckets still carries useful
edge headers (`server`, `x-vercel-id`, `cf-ray`, `x-nf-app-id`,
`x-akamai-request-id`) that identify the CDN stack.

### Multi-part TLD awareness

`_infer_apex` (used to build the wildcard control probe URL) recognises
~150 second-level suffixes so that `shop.example.co.uk` correctly
resolves to `example.co.uk` instead of the nonsense string `co.uk`.
Covers UK, AU, NZ, JP, KR, CN, IN, PK, BD, NP, LK, SG, MY, PH, VN, ID,
TH, BR, MX, AR, CO, PE, UA, TR, ZA, KE, NG, GH, TZ, UG, ZW, EG, IL.

### Baseline calibration against bot-walls

Content-diff filtering (both in `enumerate` and in `check_alive`)
memorises what a **known-fake name** looks like and drops everything
matching that signature. The failure mode: when Vercel or Cloudflare
serves its challenge page to our **baseline probes themselves**, we
memorise the wall instead of the real wildcard catchall. Then every
real wildcard 404 looks "different from the memorised wall" and
slips through as if it were a real subdomain.

Both stages now calibrate defensively:

**`_active_dns_verify` in `tools/enumerate.py`**
- 10 baseline nonsense-name probes (was 6). Higher probability that at
  least one breaks through the wall.
- Wall signatures (Vercel Checkpoint, Cloudflare Turnstile, Akamai,
  etc.) are excluded from `baseline_sigs` when baselines respond —
  one walled probe cannot poison the calibration.
- **Self-healing**: if every baseline got walled or timed out, use the
  most-common non-wall sig among the ~500 candidates as the catchall.
- **Dominant-wall override**: when a wall sig itself appears on 15+
  hosts (or half of all probed responses), the edge is serving it to
  real and fake names uniformly. In that scenario the wall IS the
  catchall and is added back to `baseline_sigs` so those names drop
  out too.
- **Error-status cluster override**: any 4xx or 5xx sig observed on
  5+ hosts is a shared handler (real apps don't cluster on errors at
  that scale), so it's treated as catchall.

**`_http_wildcard_probe_sig` in `tools/alive.py`**
- 3 control nonsense-name probes (was 1) with majority vote over
  non-wall responses. Falls back to `None` when all 3 got walled so
  the caller skips filtering safely rather than mis-flagging real
  subs as wildcard noise.

Tested on a wildcard-CDN target: pre-fix `full_recon` returned 43
subs with 31 mixed real-and-fake bot_walled entries. Post-fix same
target returns 8-12 subs with 5-7 bot_walled entries all pointing
to legitimate deployments.

### How must-probe avoids wildcard noise

The `must-probe` curated stage (`autodiscover`, `assets`, `docs`,
`git`, `admin`, `cpanel`, `smtp`, `mx`, `webmail`, ...) is a
DNS-only pass designed to catch services that live on totally
**separate infrastructure** from the wildcard pool. Example: on a
Vercel-hosted target `*.example.com` returns Vercel edge IPs but
`mail.example.com` might CNAME to `mail.mailprovider.example` on an
unrelated IP (e.g. a Roundcube host on `45.8.227.100`). A
naive wildcard filter would drop that real mail host.

To make this safe the tool uses **strict zero-overlap rule**:

```
probe 15 random nonsense names  -> wildcard IP pool and CNAME pool
                                   (15 probes because edge CDNs
                                    rotate 2 IPs per response from
                                    a pool of 4+; more probes =
                                    better pool coverage)

for each of the 40 must-probe labels:
    resolve CNAME and A records
    if any CNAME overlaps wild_cnames -> drop (wildcard noise)
    if any IP  overlaps wild_ips      -> drop (wildcard noise)
    otherwise                          -> keep (genuinely different)
```

The "otherwise keep" branch fires exactly when the name looks like
real distinct infra. Example with `xinuty.com`:

```
wild_ips     = {216.198.79.1, .65, 64.29.17.1, .65}   (Vercel pool)
mail.xinuty.com        -> A [45.8.227.100]  CNAME webmail.rabhost.com
                         no overlap  -> KEEP   (real Roundcube host)
api.xinuty.com         -> A [216.198.79.1, 64.29.17.1]  CNAME []
                         overlaps    -> DROP   (pure wildcard noise)
autodiscover.xinuty.com-> A [64.29.17.1, .65]           CNAME []
                         overlaps    -> DROP
docs.xinuty.com        -> A [216.198.79.65, 64.29.17.1] CNAME []
                         overlaps    -> DROP
```

Real-world result on the fixed pipeline: xinuty must-probe returns
**1 host** (`mail.xinuty.com`) instead of the 10 wildcards and
non-overlapping fakes the loose check produced earlier.

### Honest limits

A host stays hidden only when all three hold: no certificate-
transparency entry, no Wayback archive, and the CDN answers every name
identically even to a Chrome-fingerprinted request. The residual case
is a property of the target's infrastructure, not a gap in this tool.
Going beyond Tier 1 (TLS and HTTP/2 fingerprint) requires a real headless
browser (Playwright / patchright). That is deliberately **not shipped**
here because it adds ~300 MB RAM per worker and 100-200 ms per host,
which breaks the "runs on your laptop" contract of this MCP server.


## Install

Everything installs **self-contained on the drive that holds the
project folder** (SSD / USB / internal disk). No writes to `C:\`
except Python's own pip cache. Nothing is registered in the system
PATH. Unplug the drive, plug it into another machine, everything
still works.

### What gets installed and what each piece is for

| Item | Required? | Purpose | Where it lives |
|---|---|---|---|
| Python 3.10 + | yes | Runtime for the MCP server | Your existing install |
| `curl_cffi` | yes | Chrome TLS fingerprint to survive Vercel and Cloudflare bot-walls | `.venv\Lib\site-packages\` |
| `subfinder`, `httpx`, `dnsx`, `nuclei`, `amass` binaries | optional but recommended | Faster and more accurate recon than the Python fallbacks | `.\bin\` on the same drive |
| `nuclei-templates` community pack | needed only for `scan_vulnerabilities` | 5000+ CVE and misconfig signatures nuclei matches against | `.\bin\nuclei-templates\` on the same drive |
| 11 passive API sources | no | subfinder already wraps them; nothing to install | Free internet APIs |

### 1. Python dependencies

```powershell
cd offsec-mcp
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Recon binaries and nuclei templates (optional but recommended)

```powershell
# Windows
Set-ExecutionPolicy -Scope Process Bypass -Force
.\installers\install-tools.ps1

# Linux / macOS
bash installers/install-tools.sh
```

The script:
- downloads the latest stable Windows/Linux/macOS releases of each
  tool from GitHub
- extracts each `.exe` (or Linux binary) into `.\bin\`
- **bootstraps the nuclei template pack into `.\bin\nuclei-templates\`**
  so scanning works out of the box and nothing lands on the host
  machine's `C:\Users\<you>\nuclei-templates\`

Binaries land project-local and do **not** touch system PATH.

**Skip step 2 entirely and you can still enumerate, check liveness,
detect takeovers and harvest JS endpoints** — every tool has a Python
fallback. Only `scan_vulnerabilities` genuinely needs the `nuclei`
binary and template pack.

### 2a. Bootstrap nuclei templates manually (only if step 2 was skipped)

```powershell
# Windows
.\bin\nuclei.exe -update-templates -ud .\bin\nuclei-templates

# Linux / macOS
./bin/nuclei -update-templates -ud ./bin/nuclei-templates
```

Takes ~30-60s. After this `full_recon` returns real CVE findings
instead of `nuclei exit=2 with no templates`.

### 3. Run the MCP server
```powershell
python server.py
```
You'll see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Verify it is alive (open a second PowerShell window):
```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```
Returns `status: ok` plus the list of 13 MCP tools and which external binaries were detected on your `bin/` directory.

### 4. Connect LlamaFile
Open LlamaFile → **Add New MCP Server** → paste:
```
http://127.0.0.1:8000/sse
```
Click **Add**. The 13 tools above appear in the tool list.

**⚠ Raise the MCP tool timeout before scanning big targets.** LlamaFile's
default "Timeout for individual MCP tool calls" is 300s. On a target with
**no wildcard DNS** (e.g. most bug-bounty scopes) `enumerate_subdomains`
runs the full 110k-label dnsx sweep and can take **5-8 minutes** end-to-end.
Bump the timeout to **900s** in LlamaFile Settings → MCP → timeout field
beforehand, or you'll get `MCP error -32001: Request timed out` and no
results. Wildcard targets (Vercel / Netlify / CloudFront catch-all) finish
in 30-60s and need no change.

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
├── server.py            # MCP server entry point, registers 9 tools, runs SSE
├── config.py            # detects binaries in ./bin/ or system PATH
├── storage.py           # saves/reads ./output/*.json
├── tools/
│   ├── _http.py         # Tier 1 shared HTTP stack: curl_cffi chrome120
│   │                    #   with 4-layer fallback to requests; exports
│   │                    #   strict_get / strict_head used by every other
│   │                    #   tool that talks to live hosts
│   ├── enumerate.py     # 11 passive sources + DNS brute + Altdns-style
│   │                    #   permutations + active-dns verify (Python
│   │                    #   path uses strict_get) + Wayback crawl
│   ├── alive.py         # Tier 1 concurrent probe (10 threads) + 3-bucket
│   │                    #   post-processing: _split_stale (length and
│   │                    #   body-signature), _split_bot_walled (title
│   │                    #   patterns), _split_wildcard_http (control
│   │                    #   probe on apex), _strip_private_fields
│   ├── resolve.py       # dnsx + dnspython
│   ├── js_harvest.py    # HTML and JS deep-parse for endpoints, secrets,
│   │                    #   hidden hosts (skips bot-walled URLs)
│   ├── sensitive.py     # ~60 path probes (.git/HEAD, .env, actuator,
│   │                    #   backup.zip, phpinfo, etc.) with severity tags
│   ├── waf.py           # 21 CDN/WAF signatures via headers and body
│   ├── archive.py       # Wayback CDX deep harvest
│   ├── vuln.py          # nuclei
│   └── takeover.py      # pure-Python dangling-CNAME check
├── installers/
│   ├── install-tools.ps1
│   └── install-tools.sh
├── bin/                 # downloaded binaries (gitignored)
├── output/              # saved scans (gitignored)
├── requirements.txt     # includes curl-cffi>=0.6
├── .gitignore
├── LICENSE              # MIT
└── README.md
```

## How the fallback logic works

Every tool file does the same thing:

1. Ask `config.find_tool("name")` if the binary is installed
2. If yes → run it via `subprocess`, parse its output
3. If no → use a pure-Python equivalent
4. Return a dict with an `engine` key so the LLM knows which ran

For tools that talk to **live target hosts** (check_alive, js_harvest,
sensitive_files, waf_fingerprint, and the active-DNS verify stage in
enumerate), the Python equivalent is `strict_get` from `tools/_http.py`
which uses a **Tier 1 four-layer fallback chain**:

```
curl_cffi(impersonate="chrome120", verify=True)   # preferred
   ↓ TLS or other error
curl_cffi(impersonate="chrome120", verify=False)  # self-signed certs
   ↓ curl_cffi unavailable at install time
requests (verify=True)                            # plain fingerprint
   ↓ SSL error
requests (verify=False)                           # last resort
```

`engine` in the response is set to whichever layer actually carried
the request (`python-curl_cffi` or `python-requests`).

For tools that talk to **third-party OSINT APIs** (crt.sh, CertSpotter,
AlienVault, HackerTarget, RapidDNS, Wayback CDX, bgp.he.net,
ip.thc.org), plain `requests.get` is used directly because those
services rate-limit by IP, not by TLS fingerprint. curl_cffi provides
no benefit there and only adds overhead.

Result: the demo never breaks, whether or not the user installed the
tools or curl-cffi.

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
