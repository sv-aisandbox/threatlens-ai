<#
.SYNOPSIS
  Starts the whole ThreatLens AI stack locally: databases, Keycloak, Python service, Spring backend and web UI.

.DESCRIPTION
  Everything listens on 127.0.0.1 only. Safe to run again: finished steps are skipped or are idempotent.
  Logs go to logs\, process ids to .run\pids.json (stop with scripts\stop-all.ps1).

.PARAMETER Offline
  Load the recorded CVE-2021-44228 and CISA KEV fixtures instead of downloading them. Use when you have no network.

.PARAMETER SkipData
  Do not reload the synthetic seed graph and the demo CVE (keeps whatever is in Memgraph).

.PARAMETER Dev
  Run the web UI with `next dev` instead of a production build (slower first load, hot reload).
#>
[CmdletBinding()]
param([switch]$Offline, [switch]$SkipData, [switch]$Dev)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "ERROR: $text" -ForegroundColor Red; exit 1 }

# ---- PATH and prerequisites -------------------------------------------------------------------------------------
$env:Path = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")
$dockerBin = "C:\Program Files\Docker\Docker\resources\bin"
if (-not (Get-Command docker -ErrorAction SilentlyContinue) -and (Test-Path $dockerBin)) { $env:Path += ";$dockerBin" }

foreach ($tool in @(
        @{ Name = "docker"; Hint = "Install Docker Desktop and start it." },
        @{ Name = "uv"; Hint = "Install uv: https://docs.astral.sh/uv/" },
        @{ Name = "node"; Hint = "Install Node.js 24 or newer." },
        @{ Name = "pnpm"; Hint = "Run: npm install -g pnpm" })) {
    if (-not (Get-Command $tool.Name -ErrorAction SilentlyContinue)) { Fail "$($tool.Name) not found. $($tool.Hint)" }
}
if (-not $env:JAVA_HOME -or -not (Test-Path (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    $java = Get-Command java -ErrorAction SilentlyContinue
    if (-not $java) { Fail "JDK 21 not found. Install a JDK 21 and set JAVA_HOME." }
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker is installed but not running. Start Docker Desktop and retry." }

# ---- .env -------------------------------------------------------------------------------------------------------
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env"; Write-Host "Created .env from .env.example (local demo values)." }
$envFile = @{}
Get-Content ".env" | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$' -and -not $_.TrimStart().StartsWith("#")) {
        $envFile[$Matches[1]] = $Matches[2]
        Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
    }
}
if (-not $env:INTERNAL_JWT_SECRET -or $env:INTERNAL_JWT_SECRET.Length -lt 32 -or $env:INTERNAL_JWT_SECRET -like "change-me*") {
    $bytes = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $env:INTERNAL_JWT_SECRET = [Convert]::ToBase64String($bytes)
    $line = "INTERNAL_JWT_SECRET=$($env:INTERNAL_JWT_SECRET)"
    $text = Get-Content ".env" -Raw
    if ($text -match "(?m)^INTERNAL_JWT_SECRET=") { $text = [regex]::Replace($text, "(?m)^INTERNAL_JWT_SECRET=.*$", $line) } else { $text += "`n$line`n" }
    Set-Content ".env" $text -NoNewline
    Write-Host "Generated INTERNAL_JWT_SECRET in .env (git-ignored)."
}
if (-not $env:POSTGRES_PASSWORD -or $env:POSTGRES_PASSWORD -eq "change-me") {
    Write-Host "NOTE: POSTGRES_PASSWORD in .env is still the placeholder; fine for a local-only demo."
}

New-Item -ItemType Directory -Force logs, .run | Out-Null
$pids = @{}
function Wait-Http($url, $name, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3 | Out-Null; return }
        catch { if ($_.Exception.Response) { return } }   # any HTTP answer, even 401/404, means the server is up
        Start-Sleep -Seconds 2
    }
    Fail "$name did not answer at $url within $seconds s. See logs\."
}
function Start-Service($name, $file, $arguments, $workdir, $log) {
    $p = Start-Process -FilePath $file -ArgumentList $arguments -WorkingDirectory $workdir -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $Root "logs\$log.out.log") -RedirectStandardError (Join-Path $Root "logs\$log.err.log")
    $script:pids[$name] = $p.Id
    $script:pids | ConvertTo-Json | Set-Content (Join-Path $Root ".run\pids.json")
}

# stop anything from a previous run of this script
if (Test-Path ".run\pids.json") { & "$PSScriptRoot\stop-all.ps1" -KeepInfra | Out-Null }

# ---- infrastructure ---------------------------------------------------------------------------------------------
Step "Starting Memgraph and PostgreSQL"
docker compose up -d --wait; if ($LASTEXITCODE) { Fail "docker compose up failed" }
Step "Applying database migrations"
docker compose --profile migrate run --rm flyway; if ($LASTEXITCODE) { Fail "flyway migrate failed" }
Step "Starting Keycloak (first start takes about a minute)"
docker compose --profile auth up -d --wait keycloak; if ($LASTEXITCODE) { Fail "keycloak did not become healthy" }

# ---- data -------------------------------------------------------------------------------------------------------
Push-Location intelligence-service
try {
    Step "Installing Python dependencies"
    uv sync; if ($LASTEXITCODE) { Fail "uv sync failed" }
    if (-not $SkipData) {
        Step "Loading the synthetic demo graph"
        uv run python -m ingestion.seed_loader --reset; if ($LASTEXITCODE) { Fail "seed load failed" }
        Step "Loading CVE-2021-44228 and CISA KEV flags and matching them to the inventory"
        if ($Offline) { uv run python -m ingestion.demo_data --offline } else { uv run python -m ingestion.demo_data }
        if ($LASTEXITCODE) { Fail "demo data load failed" }
    }
}
finally { Pop-Location }

# ---- services ---------------------------------------------------------------------------------------------------
Step "Starting the Python intelligence service (127.0.0.1:8000)"
Start-Service "python" "uv" "run uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000" (Join-Path $Root "intelligence-service") "python"
Wait-Http "http://127.0.0.1:8000/internal/v1/overview" "Python service" 60

Step "Starting the Spring Boot backend (127.0.0.1:8080), first start compiles and can take a minute or two"
Start-Service "backend" "cmd.exe" "/c .\mvnw.cmd -q spring-boot:run" (Join-Path $Root "backend") "backend"
Wait-Http "http://127.0.0.1:8080/actuator/health" "Spring backend" 240

Step "Starting the web UI (127.0.0.1:3000)"
if (-not $env:NEXTAUTH_SECRET) {
    $bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $env:NEXTAUTH_SECRET = [Convert]::ToBase64String($bytes)   # new each start: old browser sessions simply sign in again
}
$env:NEXTAUTH_URL = "http://127.0.0.1:3000"
$env:KEYCLOAK_ISSUER = "http://127.0.0.1:8081/realms/threatlens"
$env:KEYCLOAK_WEB_CLIENT_ID = "threatlens-web"
$env:BACKEND_URL = "http://127.0.0.1:8080"
$env:NEXT_TELEMETRY_DISABLED = "1"
$front = Join-Path $Root "frontend"
Push-Location $front
try {
    pnpm install --frozen-lockfile; if ($LASTEXITCODE) { Fail "pnpm install failed" }
    if (-not $Dev) { pnpm build; if ($LASTEXITCODE) { Fail "next build failed" } }
}
finally { Pop-Location }
$nextArgs = if ($Dev) { "/c pnpm exec next dev --hostname 127.0.0.1 --port 3000" } else { "/c pnpm exec next start --hostname 127.0.0.1 --port 3000" }
Start-Service "web" "cmd.exe" $nextArgs $front "web"
Wait-Http "http://127.0.0.1:3000/login" "Web UI" 90

Write-Host "`nThreatLens AI is running." -ForegroundColor Green
Write-Host @"

  Web UI           http://127.0.0.1:3000          (sign in with a demo user below)
  Keycloak         http://127.0.0.1:8081          (identity provider, demo realm 'threatlens')
  Spring API       http://127.0.0.1:8080          (docs/api/threatlens.http)
  Python service   http://127.0.0.1:8000          (internal; needs a service token)

  Demo users (password: demo-password)
    alice-admin    ADMIN             TENANT-DEMO   can sync sources and upload inventory
    bob-analyst    SECURITY_ANALYST  TENANT-DEMO   can use the AI analyst
    carol-viewer   VIEWER            TENANT-DEMO   read-only; the analyst and sync are refused by the server
    dave-analyst   SECURITY_ANALYST  TENANT-OTHER  sees a different organization's data only

  Try: sign in as bob-analyst, open Vulnerabilities -> CVE-2021-44228, then AI analyst ->
       "Which of my production assets are affected by CVE-2021-44228, and how sure are we?"

  Logs: logs\    Stop: scripts\stop-all.ps1
"@
if ($env:MODEL_PROVIDER -ne "anthropic") { Write-Host "  The AI analyst uses the built-in mock model (MODEL_PROVIDER=mock): offline, no key, deterministic." }
