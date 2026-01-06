@echo off
REM ============================================
REM Silkroad Online Registration - Quick Start
REM ============================================

REM Database Configuration
set DB_SERVER=localhost
set DB_PORT=1433
set DB_USER=sa
set DB_DATABASE=SRO_VT_ACCOUNT

REM Server Configuration
set SERVER_PORT=8080

REM TLS Configuration (set to true to enable HTTPS)
set TLS_ENABLED=false
set TLS_CERT=./certs/server.crt
set TLS_KEY=./certs/server.key

REM ============================================
REM Prompt for database password
REM ============================================

echo.
echo Silkroad Online Registration Server
echo ====================================
echo.
set /p DB_PASSWORD=Enter database password:

if "%DB_PASSWORD%"=="" (
    echo Error: Password cannot be empty
    pause
    exit /b 1
)

REM ============================================
REM Start the application
REM ============================================

echo.
echo Starting server...
echo Database: %DB_SERVER%:%DB_PORT%
echo Server Port: %SERVER_PORT%
echo.

REM Check if compiled binary exists
if exist sroreg.exe (
    echo Using compiled binary: sroreg.exe
    echo.
    sroreg.exe
) else (
    echo Binary not found. Running with 'go run main.go'
    echo Make sure Go is installed on your system.
    echo.
    go run main.go
)

REM Keep window open if there's an error
if errorlevel 1 (
    echo.
    echo An error occurred. Press any key to exit...
    pause >nul
)
