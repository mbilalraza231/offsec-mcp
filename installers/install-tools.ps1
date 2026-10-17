# installers/install-tools.ps1
# Downloads the latest stable Windows binaries for the popular free recon tools
# into .\bin\ (project-local, does NOT touch system PATH).
#
# Usage (from project root, PowerShell):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\installers\install-tools.ps1

$ErrorActionPreference = "Stop"
$BinDir = Join-Path $PSScriptRoot "..\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

function Get-LatestAssetUrl {
    param([string]$Owner, [string]$Repo, [string]$Pattern)
    $api = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    Write-Host "  querying $Owner/$Repo latest release..." -ForegroundColor DarkGray
    $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "offsec-mcp-installer" }
    $asset = $release.assets | Where-Object { $_.name -like $Pattern } | Select-Object -First 1
    if (-not $asset) { throw "no asset matching '$Pattern' in $Owner/$Repo" }
    return $asset.browser_download_url, $asset.name
}

function Expand-ZipTo {
    param([string]$ZipPath, [string]$Dest, [string]$ExeName, [string]$OutExe)
    $tmp = Join-Path $env:TEMP ("offsec-mcp-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Expand-Archive -Path $ZipPath -DestinationPath $tmp -Force
    $found = Get-ChildItem -Path $tmp -Recurse -Filter $ExeName | Select-Object -First 1
    if (-not $found) { throw "$ExeName not found inside $ZipPath" }
    Copy-Item $found.FullName (Join-Path $Dest $OutExe) -Force
    Remove-Item -Recurse -Force $tmp
}

$tools = @(
    @{ Name = "subfinder"; Owner = "projectdiscovery"; Repo = "subfinder";
       Pattern = "*windows_amd64.zip"; Exe = "subfinder.exe"; Out = "subfinder.exe" },
    @{ Name = "httpx";     Owner = "projectdiscovery"; Repo = "httpx";
       Pattern = "*windows_amd64.zip"; Exe = "httpx.exe";     Out = "httpx.exe" },
    @{ Name = "dnsx";      Owner = "projectdiscovery"; Repo = "dnsx";
       Pattern = "*windows_amd64.zip"; Exe = "dnsx.exe";      Out = "dnsx.exe" },
    @{ Name = "nuclei";    Owner = "projectdiscovery"; Repo = "nuclei";
       Pattern = "*windows_amd64.zip";     Exe = "nuclei.exe";    Out = "nuclei.exe" },
    @{ Name = "amass";     Owner = "owasp-amass";      Repo = "amass";
       Pattern = "*windows*amd64*.zip";    Exe = "amass.exe";     Out = "amass.exe" }
)

Write-Host "`n=== offsec-mcp tool installer ===" -ForegroundColor Cyan
foreach ($t in $tools) {
    Write-Host "`n[$($t.Name)]" -ForegroundColor Yellow
    try {
        $url, $assetName = Get-LatestAssetUrl -Owner $t.Owner -Repo $t.Repo -Pattern $t.Pattern
        $zip = Join-Path $env:TEMP $assetName
        Write-Host "  downloading $assetName"
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        Expand-ZipTo -ZipPath $zip -Dest $BinDir -ExeName $t.Exe -OutExe $t.Out
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Write-Host "  installed -> $BinDir\$($t.Out)" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  skipping - the MCP server will use Python fallback for this one" -ForegroundColor DarkGray
    }
}

Write-Host "`n=== done ===" -ForegroundColor Cyan
Write-Host "Binaries in: $((Resolve-Path $BinDir).Path)"
