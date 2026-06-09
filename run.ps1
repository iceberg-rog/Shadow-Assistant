# Fleet Panel launcher (Windows)
# Usage: right-click > Run with PowerShell, or: powershell -ExecutionPolicy Bypass -File run.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# 1) docker CLI present?
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker is not installed." -ForegroundColor Red
  Write-Host "Install Docker Desktop, then re-run: https://www.docker.com/products/docker-desktop/"
  exit 1
}

# 2) docker daemon actually running?
docker info *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Docker Desktop is installed but NOT running." -ForegroundColor Red
  Write-Host "Open Docker Desktop, wait until it says 'Engine running' (steady whale icon)," -ForegroundColor Yellow
  Write-Host "then run this again." -ForegroundColor Yellow
  exit 1
}

# 3) first-run .env with a random admin password
if (-not (Test-Path ".env")) {
  $chars  = (48..57) + (65..90) + (97..122)
  $admin  = -join ($chars | Get-Random -Count 16 | ForEach-Object { [char]$_ })
  $secret = -join ((48..57)+(97..102) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
  "DASH_ADMIN_PASS=$admin`nFLASK_SECRET=$secret" | Set-Content -Encoding ascii ".env"
  Write-Host "Created .env  |  Dashboard password: $admin" -ForegroundColor Green
}

# 4) build + start
Write-Host "Starting Fleet Panel (first build can take a few minutes)..." -ForegroundColor Cyan
docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
  Write-Host "docker compose failed (see the error above)." -ForegroundColor Red
  exit 1
}

# 5) verify the panel actually answers before claiming success
$pass = (Select-String -Path ".env" -Pattern 'DASH_ADMIN_PASS=(.+)').Matches.Groups[1].Value
$up = $false
foreach ($i in 1..15) {
  try {
    $r = Invoke-WebRequest -Uri "http://localhost:8088/login" -UseBasicParsing -TimeoutSec 3
    if ($r.StatusCode -eq 200) { $up = $true; break }
  } catch { Start-Sleep -Seconds 2 }
}
Write-Host ""
if ($up) {
  Write-Host "Fleet Panel is up:  http://localhost:8088/login" -ForegroundColor Green
  Write-Host "Login password:     $pass" -ForegroundColor Green
  Start-Process "http://localhost:8088/login"
} else {
  Write-Host "Container started but the panel did not answer yet." -ForegroundColor Yellow
  Write-Host "Check logs:  docker compose logs -f" -ForegroundColor Yellow
  Write-Host "Password (in .env): $pass"
}
