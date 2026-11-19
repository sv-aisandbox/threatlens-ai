<#
.SYNOPSIS
  Stops the web UI, Spring backend and Python service started by start-all.ps1, and the Docker containers.

.PARAMETER KeepInfra
  Leave Memgraph, PostgreSQL and Keycloak running.

.PARAMETER Reset
  Also delete all local database data (docker compose down -v).
#>
[CmdletBinding()]
param([switch]$KeepInfra, [switch]$Reset)

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:Path = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")
$dockerBin = "C:\Program Files\Docker\Docker\resources\bin"
if (-not (Get-Command docker -ErrorAction SilentlyContinue) -and (Test-Path $dockerBin)) { $env:Path += ";$dockerBin" }

$file = Join-Path $Root ".run\pids.json"
if (Test-Path $file) {
    $pids = Get-Content $file -Raw | ConvertFrom-Json
    foreach ($prop in $pids.PSObject.Properties) {
        $id = [int]$prop.Value
        if (Get-Process -Id $id -ErrorAction SilentlyContinue) {
            taskkill /PID $id /T /F *> $null
            Write-Host "Stopped $($prop.Name) (pid $id)"
        }
    }
    Remove-Item $file -Force
}

# a Spring/Next child can outlive its wrapper: free the ports as well
foreach ($port in 3000, 8000, 8080) {
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            # only our own runtimes: never a Docker port-forwarder (Memgraph Lab also uses 3000 when enabled)
            if ($p -and $p.ProcessName -match '^(node|java|python|uvicorn|uv)$') {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                Write-Host "Freed port $port ($($p.ProcessName))"
            }
        }
}

if (-not $KeepInfra) {
    if ($Reset) { docker compose --profile auth --profile migrate down -v } else { docker compose --profile auth --profile migrate down }
}
