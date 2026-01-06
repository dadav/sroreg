# ============================================
# Silkroad Online Registration - Quick Start
# ============================================

# Database Configuration
$env:DB_SERVER = "localhost"
$env:DB_PORT = "1433"
$env:DB_USER = "sa"
$env:DB_DATABASE = "SRO_VT_ACCOUNT"

# Server Configuration
$env:SERVER_PORT = "8080"

# TLS Configuration (set to $true to enable HTTPS)
$env:TLS_ENABLED = "false"
$env:TLS_CERT = "./certs/server.crt"
$env:TLS_KEY = "./certs/server.key"

# ============================================
# Prompt for database password
# ============================================

Write-Host ""
Write-Host "Silkroad Online Registration Server" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

$SecurePassword = Read-Host "Enter database password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$env:DB_PASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

if ([string]::IsNullOrEmpty($env:DB_PASSWORD)) {
    Write-Host ""
    Write-Host "Error: Password cannot be empty" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# ============================================
# Start the application
# ============================================

Write-Host ""
Write-Host "Starting server..." -ForegroundColor Green
Write-Host "Database: $env:DB_SERVER`:$env:DB_PORT"
Write-Host "Server Port: $env:SERVER_PORT"
Write-Host ""

# Check if compiled binary exists
if (Test-Path "sroreg.exe") {
    Write-Host "Using compiled binary: sroreg.exe" -ForegroundColor Cyan
    Write-Host ""
    .\sroreg.exe
} else {
    Write-Host "Binary not found. Running with 'go run main.go'" -ForegroundColor Yellow
    Write-Host "Make sure Go is installed on your system." -ForegroundColor Yellow
    Write-Host ""
    go run main.go
}

# Keep window open if there's an error
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "An error occurred. Press any key to exit..." -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
