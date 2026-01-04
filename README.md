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
- Duplicate username checking
- MD5 password hashing
- Automatic security level assignment (sec_primary and sec_content set to 3)
- Fully responsive design
- Form never exceeds viewport height

## Design

- **Left Panel**: Beautiful background image with gradient overlay
- **Right Panel**: Registration form with clean, modern styling
- **Mobile Responsive**: Adapts to vertical layout on smaller screens

## Database Configuration

- Server: localhost:1433
- Database: SRO_VT_ACCOUNT
- Table: dbo.TB_User
- Columns used: StrUserID, password, Email, sec_primary, sec_content

## Running the Application

1. Make sure SQL Server is running on localhost:1433
2. Install dependencies:
   ```bash
   go mod download
   ```
3. Run the server:
   ```bash
   go run main.go
   ```
4. Open your browser and navigate to: http://localhost:8080

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
