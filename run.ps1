# Fleet Panel launcher (Windows)
# Checks prerequisites (Git, Docker Desktop) and auto-installs missing ones via winget,
# then auto-starts the Docker engine and brings the panel up.
# NOTE: no $ErrorActionPreference='Stop' on purpose - native tools (docker/winget) write
# to stderr, which under 'Stop' would abort the script. We gate on exit codes instead.
Set-Location $PSScriptRoot

function Have($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function Refresh-Path {
  $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
              [Environment]::GetEnvironmentVariable("Path","User")
}
function Test-DockerUp { cmd /c "docker info >NUL 2>NUL"; return ($LASTEXITCODE -eq 0) }

# ---- prerequisite: winget (needed to auto-install the rest) ----
$canWinget = Have winget
if (-not $canWinget) {
  Write-Host "winget (App Installer) not found - can't auto-install prerequisites." -ForegroundColor Yellow
  Write-Host "Install 'App Installer' from the Microsoft Store, or install Git/Docker manually, then re-run."
}

# ---- prerequisite: Git ----
if (-not (Have git)) {
  Write-Host "Git not found." -ForegroundColor Yellow
  if ($canWinget) {
    Write-Host "Installing Git via winget..." -ForegroundColor Cyan
    winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements --silent
    Refresh-Path
  }
  if (-not (Have git)) { Write-Host "Could not install Git. Get it from https://git-scm.com/download/win" -ForegroundColor Red }
}

# ---- prerequisite: Docker Desktop ----
if (-not (Have docker)) {
  Write-Host "Docker not found." -ForegroundColor Yellow
  if ($canWinget) {
    Write-Host "Installing Docker Desktop via winget (large download)..." -ForegroundColor Cyan
    winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
    Refresh-Path
    Write-Host "Docker Desktop installed. A Windows RESTART is usually required (WSL2)." -ForegroundColor Yellow
  }
  if (-not (Have docker)) {
    Write-Host "Docker still not on PATH. Restart Windows, then run this again." -ForegroundColor Red
    exit 1
  }
}

# ---- ensure the Docker engine is running (auto-start Docker Desktop) ----
if (-not (Test-DockerUp)) {
  Write-Host "Docker engine not running - starting Docker Desktop..." -ForegroundColor Yellow
  $paths = @(
    "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
    "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
    "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
  )
  $exe = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($exe) { Start-Process $exe }
  else { Write-Host "Couldn't find Docker Desktop.exe - open Docker Desktop manually." -ForegroundColor Yellow }

  Write-Host "Waiting for the Docker engine (first start can take 1-2 minutes)" -NoNewline -ForegroundColor Cyan
  $ready = $false
  for ($i = 0; $i -lt 80; $i++) {
    if (Test-DockerUp) { $ready = $true; break }
    Start-Sleep -Seconds 3
    Write-Host "." -NoNewline
  }
  Write-Host ""
  if (-not $ready) {
    Write-Host "Docker did not come up in time. Open Docker Desktop, wait for 'Engine running', then re-run." -ForegroundColor Red
    exit 1
  }
  Write-Host "Docker engine is up." -ForegroundColor Green
}

# ---- first-run .env ----
if (-not (Test-Path ".env")) {
  $chars  = (48..57) + (65..90) + (97..122)
  $admin  = -join ($chars | Get-Random -Count 16 | ForEach-Object { [char]$_ })
  $secret = -join ((48..57)+(97..102) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
  "DASH_ADMIN_PASS=$admin`nFLASK_SECRET=$secret" | Set-Content -Encoding ascii ".env"
  Write-Host "Created .env  |  Dashboard password: $admin" -ForegroundColor Green
}

# ---- build + start ----
Write-Host "Starting Fleet Panel (first build can take a few minutes)..." -ForegroundColor Cyan
cmd /c "docker compose up -d --build"
if ($LASTEXITCODE -ne 0) {
  Write-Host "docker compose failed (see the error above)." -ForegroundColor Red
  exit 1
}

# ---- verify the panel answers ----
$pass = (Select-String -Path ".env" -Pattern 'DASH_ADMIN_PASS=(.+)').Matches.Groups[1].Value
$up = $false
for ($i = 0; $i -lt 20; $i++) {
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
