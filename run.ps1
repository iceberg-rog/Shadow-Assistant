# Fleet Panel launcher (Windows)
# Usage: right-click > Run with PowerShell, or: powershell -ExecutionPolicy Bypass -File run.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker not found. Install Docker Desktop and start it, then re-run." -ForegroundColor Red
  Write-Host "https://www.docker.com/products/docker-desktop/"
  exit 1
}

if (-not (Test-Path ".env")) {
  $chars  = (48..57) + (65..90) + (97..122)
  $admin  = -join ($chars | Get-Random -Count 16 | ForEach-Object { [char]$_ })
  $secret = -join ((48..57)+(97..102) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
  "DASH_ADMIN_PASS=$admin`nFLASK_SECRET=$secret" | Set-Content -Encoding ascii ".env"
  Write-Host "Created .env  |  Dashboard password: $admin" -ForegroundColor Green
}

Write-Host "Starting Fleet Panel..." -ForegroundColor Cyan
docker compose up -d --build

$pass = (Select-String -Path ".env" -Pattern 'DASH_ADMIN_PASS=(.+)').Matches.Groups[1].Value
Start-Sleep -Seconds 3
Write-Host ""
Write-Host "Fleet Panel is up:  http://localhost:8088/login" -ForegroundColor Green
Write-Host "Login password:     $pass" -ForegroundColor Green
Start-Process "http://localhost:8088/login"
