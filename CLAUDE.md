# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Silkroad Online registration website built with Go. It's a single-binary web application that connects to a Microsoft SQL Server database to handle user registrations for the Silkroad Online game.

## Common Commands

### Running the Application

**Windows Quick Start:**
```cmd
REM Option 1: Double-click start.bat and enter password when prompted
start.bat

REM Option 2: Use PowerShell script (masks password input)
start.ps1
```

**Linux/macOS:**
```bash
# Quick start with minimal config (requires DB_PASSWORD)
DB_PASSWORD=YourPassword go run main.go

# With full environment variables
export $(cat .env | xargs)
go run main.go

# With command-line flags
go run main.go --db-password YourPassword --port 8080

# With TLS enabled
TLS_ENABLED=true TLS_CERT=./certs/server.crt TLS_KEY=./certs/server.key DB_PASSWORD=YourPassword go run main.go

# Generate self-signed certificate for development
./generate-cert.sh
```

### Building

```bash
# Build for current platform
go build -o sroreg main.go

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o sroreg-linux-amd64 main.go
GOOS=windows GOARCH=amd64 go build -o sroreg-windows-amd64.exe main.go

# Test GoReleaser configuration
goreleaser check
```

### Releases

```bash
# Create and push a new release tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
# GitHub Actions will automatically build and release binaries
```

## Architecture

### Single-File Application Structure

The entire application logic is in `main.go` (263 lines). This is a deliberate design choice for simplicity and portability.

**Key Components:**

- **Configuration (lines 20-160)**: Flexible config system with precedence: defaults → env vars → CLI flags
- **HTTP Handlers (lines 162-262)**:
  - `/` - Serves registration form
  - `/register` - POST endpoint for user registration
  - `/static/` - Static file serving
- **Database Layer (lines 100-113, 209-230)**: Direct SQL queries using parameterized statements
- **Validation (lines 235-243)**: Regex-based username and email validation

### Database Integration

**Target Database:** Microsoft SQL Server (Silkroad Online schema)
- Database: `SRO_VT_ACCOUNT`
- Table: `dbo.TB_User`
- Columns: `StrUserID`, `password` (MD5 hash), `Email`, `sec_primary`, `sec_content`

**Connection:** Uses `github.com/microsoft/go-mssqldb` driver with connection pooling.

**Security:**
- All queries use parameterized statements (`@p1`, `@p2`, etc.) to prevent SQL injection
- Passwords are MD5 hashed (legacy requirement from Silkroad Online server)
- New users default to `sec_primary=3` and `sec_content=3` (non-admin accounts)

### Configuration System

Three-layer configuration (priority: CLI flags > env vars > defaults):

1. **Environment Variables:** `DB_SERVER`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_DATABASE`, `SERVER_PORT`, `TLS_ENABLED`, `TLS_CERT`, `TLS_KEY`
2. **CLI Flags:** `--db-server`, `--db-port`, `--db-user`, `--db-password`, `--db-database`, `--port`, `--tls`, `--tls-cert`, `--tls-key`
3. **Defaults:** localhost:1433, sa user, port 8080

**Required:** `DB_PASSWORD` must be set (no default for security).

### Template System

Single template at `templates/register.html` rendered by `html/template`. Template receives data maps with `Error` or `Success` keys for user feedback.

### Static Assets

Located in `static/`:
- `style.css` - Split-screen styling with yellow/black theme
- `silkroad-bg.jpg` - Background image (can be replaced)
- `logo.svg` and `logo.png` - Silkroad Online branding

## Important Implementation Notes

### Password Hashing
The application uses MD5 for password hashing (main.go:245-248). This is a **legacy requirement** from the Silkroad Online server database schema. Do not change this to a more secure algorithm (bcrypt, argon2, etc.) without also updating the game server's authentication system.

### Validation Rules
- **Username:** 4-16 characters, alphanumeric only (`^[a-zA-Z0-9]+$`)
- **Password:** Minimum 6 characters
- **Email:** Standard email regex validation
- Both frontend (HTML5 patterns) and backend validation are implemented

### TLS Support
The application can run with or without TLS:
- When TLS is enabled, requires both cert and key files
- Use `generate-cert.sh` for development self-signed certificates
- Production deployments should use reverse proxy (Caddy/Nginx) for automatic Let's Encrypt

### Release Artifacts
GoReleaser automatically includes templates and static directories in release archives (main.go:114, 118 depend on these paths being relative to the binary).

## Database Schema Expectations

The application expects this exact schema:

```sql
-- Table: dbo.TB_User in database SRO_VT_ACCOUNT
-- Columns used:
--   StrUserID (username, unique)
--   password (MD5 hash string)
--   Email (email address)
--   sec_primary (security level, set to 3)
--   sec_content (content level, set to 3)
```

## Development Workflow

1. Ensure SQL Server is running with `SRO_VT_ACCOUNT` database
2. Set `DB_PASSWORD` environment variable
3. Run with `go run main.go`
4. Access at http://localhost:8080
5. For production, use reverse proxy with automatic HTTPS

## Testing Changes

Since this is a web application:
1. Start the server with test database credentials
2. Manually test registration flow in browser
3. Verify database inserts using SQL client
4. Test TLS configuration if modified
5. Test with invalid inputs to verify validation
