# Silkroad Online Registration Website

A beautiful split-screen registration website for Silkroad Online built with Go.

## Features

- Modern split-screen design with official Silkroad Online logo
- Clean, spacious form layout with yellow/black theme
- **Comprehensive validation:**
  - Frontend: HTML5 pattern validation with instant feedback
  - Backend: Regex validation for username (alphanumeric only) and email
  - Password strength requirements (minimum 6 characters)
  - Password confirmation matching
- **SQL Injection Protection:**
  - Parameterized queries (@p1, @p2, @p3)
  - Input sanitization and validation
  - No direct string concatenation in queries
- **TLS/HTTPS Support:**
  - Optional TLS encryption for secure connections
  - Self-signed certificate generation for development
  - Production-ready with proper CA certificates
- **Flexible Configuration:**
  - Environment variables
  - Command-line flags
  - Configurable database connection and server port
- Duplicate username checking
- MD5 password hashing
- Automatic security level assignment (sec_primary and sec_content set to 3)
- Fully responsive design
- Form never exceeds viewport height

## Design

- **Left Panel**: Beautiful background image with gradient overlay
- **Right Panel**: Registration form with clean, modern styling
- **Mobile Responsive**: Adapts to vertical layout on smaller screens

## Configuration

The application can be configured using environment variables or command-line flags.

### Environment Variables

Create a `.env` file (use `.env.example` as template):

```bash
# Database Configuration
DB_SERVER=localhost
DB_PORT=1433
DB_USER=sa
DB_PASSWORD=YourPasswordHere
DB_DATABASE=SRO_VT_ACCOUNT

# Server Configuration
SERVER_PORT=8080
```

### Command-Line Flags

All settings can be overridden using command-line flags:

```bash
./sroreg --db-server localhost \
         --db-port 1433 \
         --db-user sa \
         --db-password YourPassword \
         --db-database SRO_VT_ACCOUNT \
         --port 8080
```

### TLS/HTTPS Support

The application supports TLS/HTTPS for secure connections:

**Environment Variables:**
```bash
TLS_ENABLED=true
TLS_CERT=./certs/server.crt
TLS_KEY=./certs/server.key
```

**Command-Line Flags:**
```bash
./sroreg --tls --tls-cert ./certs/server.crt --tls-key ./certs/server.key
```

**Generate Self-Signed Certificate (for development):**
```bash
./generate-cert.sh
```

This creates `certs/server.crt` and `certs/server.key` for testing purposes.

**⚠️ Important:** Self-signed certificates are for development only. In production, use certificates from a trusted Certificate Authority (CA) like Let's Encrypt.

**Running with TLS:**
```bash
# Using environment variables
TLS_ENABLED=true TLS_CERT=./certs/server.crt TLS_KEY=./certs/server.key DB_PASSWORD=YourPassword go run main.go

# Using flags
go run main.go --tls --tls-cert ./certs/server.crt --tls-key ./certs/server.key --db-password YourPassword
```

The server will be accessible at `https://localhost:8080` (or your configured port).

### Reverse Proxy Support

For production deployments, it's recommended to use a reverse proxy like Caddy or Nginx in front of the application. This provides:
- Automatic HTTPS with Let's Encrypt
- Load balancing
- Security headers
- Access logging

**Using Caddy (Recommended):**

1. Copy the example Caddyfile:
   ```bash
   cp Caddyfile.example Caddyfile
   ```

2. Edit the Caddyfile and replace `register.silkroad-example.com` with your domain

3. Run the Go application on HTTP (Caddy will handle TLS):
   ```bash
   DB_PASSWORD=YourPassword ./sroreg --port 8080
   ```

4. Start Caddy:
   ```bash
   caddy run
   ```

Caddy will automatically:
- Obtain TLS certificates from Let's Encrypt
- Handle HTTPS connections
- Forward requests to your Go application
- Renew certificates before expiration

**Using Nginx:**

Example Nginx configuration:
```nginx
server {
    listen 80;
    server_name register.silkroad-example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name register.silkroad-example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Configuration Priority

Configuration is loaded in the following order (later overrides earlier):
1. Default values (localhost:1433, port 8080)
2. Environment variables
3. Command-line flags

### Database Schema

- Database: SRO_VT_ACCOUNT
- Table: dbo.TB_User
- Columns used: StrUserID, password, Email, sec_primary, sec_content

## Running the Application

### Using Environment Variables

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and set your database password

3. Run the server:
   ```bash
   export $(cat .env | xargs)
   go run main.go
   ```

### Using Command-Line Flags

```bash
go run main.go --db-password YourPassword --port 8080
```

### Quick Start (with defaults)

```bash
DB_PASSWORD=Foobarfoobar2 go run main.go
```

The server will start on http://localhost:8080 (or the port you configured)

## Building and Releases

### Automated Releases (GitHub Actions)

The project uses GoReleaser with GitHub Actions to automatically build binaries for multiple platforms when you push a tag:

1. Create and push a new tag:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

2. GitHub Actions will automatically:
   - Build binaries for Linux (amd64, arm64) and Windows (amd64)
   - Create release archives with templates and static files included
   - Generate checksums
   - Create a GitHub release with all artifacts

### Manual Build

To build manually for your current platform:
```bash
go build -o sroreg main.go
```

To build for a specific platform:
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o sroreg-linux-amd64 main.go

# Windows
GOOS=windows GOARCH=amd64 go build -o sroreg-windows-amd64.exe main.go
```

### Release Artifacts

Each release includes:
- Pre-compiled binaries for Linux and Windows
- All necessary templates and static files
- README and documentation
- Checksums for verification

## Customization

You can replace the background image by updating `static/silkroad-bg.jpg` with your own Silkroad Online themed image.

## Project Structure

```
sroreg/
├── main.go                    # Main application with database logic
├── templates/
│   └── register.html         # Registration form template
├── static/
│   ├── style.css            # Modern split-screen styling
│   └── silkroad-bg.jpg      # Background image (can be replaced)
├── go.mod                   # Go module dependencies
└── README.md               # This file
```

## How It Works

1. User fills out the registration form with username, email, and password
2. Frontend validation ensures proper input lengths
3. Backend checks for duplicate usernames using StrUserID
4. Password is hashed using MD5
5. New user is inserted with sec_primary=3 and sec_content=3 (regular user, not admin)
6. Success or error message is displayed to the user
