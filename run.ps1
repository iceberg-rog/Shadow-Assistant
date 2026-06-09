# Fleet Panel launcher (Windows) - auto-starts Docker Desktop if needed.
# NOTE: we deliberately do NOT set $ErrorActionPreference='Stop' and we run docker
# via `cmd /c "... >NUL 2>NUL"`: native tools write progress/errors to stderr, which
# under 'Stop' would abort the script before the auto-start logic could run.
Set-Location $PSScriptRoot

function Test-DockerUp {
  cmd /c "docker info >NUL 2>NUL"
  return ($LASTEXITCODE -eq 0)
}

# 1) docker CLI present?
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker Desktop is not installed." -ForegroundColor Red
  Write-Host "Install it once (then re-run this): https://www.docker.com/products/docker-desktop/"
  Start-Process "https://www.docker.com/products/docker-desktop/"
  exit 1
}

# 2) ensure the engine is running - auto-start Docker Desktop if not
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
  for ($i = 0; $i -lt 60; $i++) {
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
cmd /c "docker compose up -d --build"
if ($LASTEXITCODE -ne 0) {
  Write-Host "docker compose failed (see the error above)." -ForegroundColor Red
  exit 1
}

# 5) verify the panel answers before claiming success
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
