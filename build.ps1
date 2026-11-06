[CmdletBinding()]
param(
    [switch]$SkipPayload,
    [switch]$SkipUi,
    [switch]$Test,
    [switch]$Bundle
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Native tools write progress to stderr; with ErrorActionPreference=Stop that
# would abort the script even on success. Run them in a relaxed scope and judge
# them by exit code instead.
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $code = 0
    try {
        & $Command
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }

    if ($code -ne 0) {
        throw "$Description failed with exit code $code"
    }
}

function Step {
    param([string]$Text)
    Write-Host ""
    Write-Host "== $Text" -ForegroundColor Cyan
}

Step "toolchain"
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm not found. Install Node.js 20 or newer."
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found. Install Rust via https://rustup.rs."
}

$nodeVersion = (node --version)
$cargoVersion = ((cargo --version) -join " ")
$cmakeStatus = if (Get-Command cmake -ErrorAction SilentlyContinue) { "present" } else { "missing" }
Write-Host "node   $nodeVersion"
Write-Host "cargo  $cargoVersion"
Write-Host "cmake  $cmakeStatus"

# ------------------------------------------------------------------ payload
if (-not $SkipPayload) {
    Step "payload (zeno-core)"
    if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
        throw "cmake not found. Install CMake >= 3.20 plus the MSVC 2022 x64 toolchain, or pass -SkipPayload."
    }

    Invoke-Native "cmake configure" {
        cmake -S zeno-core -B zeno-core/build -A x64 -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    }
    Invoke-Native "cmake build" {
        cmake --build zeno-core/build --config Release --parallel
    }

    $dll = "zeno-core/build/zeno_inject.dll"
    if (-not (Test-Path $dll)) {
        throw "$dll was not produced"
    }

    New-Item -ItemType Directory -Force -Path "src-tauri/resources" | Out-Null
    Copy-Item $dll "src-tauri/resources/zeno_inject.dll" -Force
    if (Test-Path "zeno-core/build/zeno_offsets.json") {
        Copy-Item "zeno-core/build/zeno_offsets.json" "src-tauri/resources/zeno_offsets.json" -Force
    }

    $payloadSize = (Get-Item $dll).Length
    Write-Host "payload $payloadSize bytes -> src-tauri/resources" -ForegroundColor Green
}

# ----------------------------------------------------------------------- ui
if (-not $SkipUi) {
    Step "frontend"
    if (-not (Test-Path "node_modules")) {
        Invoke-Native "npm ci" { npm ci }
    }
    Invoke-Native "npm run build" { npm run build }
}

# --------------------------------------------------------------------- test
if ($Test) {
    Step "tests"
    Invoke-Native "cargo test" {
        cargo test --manifest-path src-tauri/Cargo.toml --lib
    }
}

# ---------------------------------------------------------------------- app
Step "app (tauri)"
if (-not (Test-Path "src-tauri/resources/zeno_inject.dll")) {
    Write-Host "warning: src-tauri/resources/zeno_inject.dll is missing - the app builds but cannot inject" -ForegroundColor Yellow
}

if ($Bundle) {
    Invoke-Native "tauri build" { npm run tauri:build }
} else {
    Invoke-Native "tauri build" { npm run tauri:build -- --no-bundle }
}

$exe = "src-tauri/target/release/zeno.exe"
if (-not (Test-Path $exe)) {
    throw "$exe was not produced"
}
$exeSize = (Get-Item $exe).Length
Write-Host ""
Write-Host "built $exe ($exeSize bytes)" -ForegroundColor Green
