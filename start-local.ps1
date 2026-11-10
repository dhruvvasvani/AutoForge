param(
    [ValidateSet('backend', 'analyzer', 'frontend', 'worker')]
    [string]$Service
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Test-PortAvailable {
    param([int]$Port)

    $connection = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($connection) {
        throw "Port $Port is already in use (process ID $($connection.OwningProcess)). Stop that service before starting another copy."
    }
}

if ($Service) {
    switch ($Service) {
        'backend' {
            Set-Location $root
            $envFile = Join-Path $root '.env'
            if (-not (Test-Path $envFile)) {
                throw "Missing $envFile. Create it from .env.example and set the required local secrets."
            }

            Get-Content $envFile | ForEach-Object {
                if ($_ -match '^\s*([^#\s][^=]*)=(.*)$') {
                    $name = $Matches[1].Trim()
                    $value = $Matches[2].Trim().Trim('"').Trim("'")
                    Set-Item "Env:$name" $value
                }
            }

            foreach ($name in @('POSTGRES_PASSWORD', 'AUTOFORGE_INTERNAL_TOKEN', 'AUTOFORGE_JWT_SECRET')) {
                if (-not (Get-Item "Env:$name" -ErrorAction SilentlyContinue)) {
                    throw "Required variable $name is missing from .env."
                }
            }

            $env:SPRING_PROFILES_ACTIVE = 'prod'
            $env:SPRING_DATASOURCE_URL = 'jdbc:postgresql://127.0.0.1:5433/autoforge'
            $env:SPRING_DATASOURCE_USERNAME = 'autoforge'
            $env:SPRING_DATASOURCE_PASSWORD = $env:POSTGRES_PASSWORD
            $env:REDIS_HOST = '127.0.0.1'
            $env:REDIS_PORT = '6380'
            $env:AUTOFORGE_GITHUB_TOKEN = $env:GITHUB_TOKEN
            $env:JAVA_TOOL_OPTIONS = '-Duser.timezone=Asia/Kolkata'

            Test-PortAvailable 8089
            Set-Location (Join-Path $root '1_backend')
            & .\mvnw.cmd spring-boot:run
            if ($LASTEXITCODE -ne 0) {
                throw "Backend exited with code $LASTEXITCODE."
            }
        }
        'analyzer' {
            Test-PortAvailable 8090
            Set-Location $root
            $python = Join-Path $root '.venv\Scripts\python.exe'
            if (-not (Test-Path $python)) {
                throw "Python environment not found at $python."
            }
            & $python -m uvicorn src.dashboard_api:app --app-dir .\3_ast_analyzer --host 127.0.0.1 --port 8090
            if ($LASTEXITCODE -ne 0) {
                throw "Analyzer exited with code $LASTEXITCODE."
            }
        }
        'frontend' {
            Test-PortAvailable 5173
            Set-Location (Join-Path $root '4_frontend')
            & npm run dev -- --host 127.0.0.1
            if ($LASTEXITCODE -ne 0) {
                throw "Frontend exited with code $LASTEXITCODE."
            }
        }
        'worker' {
            Set-Location $root
            $envFile = Join-Path $root '.env'
            if (-not (Test-Path $envFile)) {
                throw "Missing $envFile. Create it from .env.example and set the required local secrets."
            }

            Get-Content $envFile | ForEach-Object {
                if ($_ -match '^\s*([^#\s][^=]*)=(.*)$') {
                    $name = $Matches[1].Trim()
                    $value = $Matches[2].Trim().Trim('"').Trim("'")
                    Set-Item "Env:$name" $value
                }
            }

            if (-not $env:AUTOFORGE_INTERNAL_TOKEN) {
                throw 'AUTOFORGE_INTERNAL_TOKEN is missing from .env.'
            }

            $env:AUTOFORGE_INTERNAL_SCAN_TOKEN = $env:AUTOFORGE_INTERNAL_TOKEN
            $env:AUTOFORGE_AI_FIX_ENABLED = 'false'
            $env:BACKEND_URL = 'http://127.0.0.1:8089'
            $env:REDIS_HOST = '127.0.0.1'
            $env:REDIS_PORT = '6380'
            $python = Join-Path $root '.venv\Scripts\python.exe'
            if (-not (Test-Path $python)) {
                throw "Python environment not found at $python."
            }

            & $python .\2_pipeline\queue\worker.py
            if ($LASTEXITCODE -ne 0) {
                throw "Pipeline worker exited with code $LASTEXITCODE."
            }
        }
    }
    exit
}

Set-Location $root
if (-not (Test-Path (Join-Path $root '.env'))) {
    throw 'Missing .env at the repository root.'
}

Write-Host 'Starting PostgreSQL and Redis...'
& docker compose up -d postgres redis
if ($LASTEXITCODE -ne 0) {
    throw 'Could not start PostgreSQL and Redis. Check that Docker Desktop is running.'
}

foreach ($port in @(8089, 8090, 5173)) {
    Test-PortAvailable $port
}

$services = @('backend', 'analyzer', 'frontend', 'worker')
foreach ($name in $services) {
    $arguments = "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Service $name"
    Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments
}

Write-Host ''
Write-Host 'Opened separate PowerShell windows for backend, analyzer, frontend, and worker.'
Write-Host 'Keep those windows open. Dashboard: http://127.0.0.1:5173'
