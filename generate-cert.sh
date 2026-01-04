#!/bin/bash
# Generate self-signed TLS certificates for development

set -e

# Create certs directory if it doesn't exist
mkdir -p certs

echo "Generating self-signed TLS certificate..."
echo "NOTE: This is for DEVELOPMENT/TESTING only. Use proper certificates in production!"
echo ""

# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Set appropriate permissions
chmod 600 certs/server.key
chmod 644 certs/server.crt

echo ""
echo "✓ Certificate generated successfully!"
echo ""
echo "Files created:"
echo "  - certs/server.crt (certificate)"
echo "  - certs/server.key (private key)"
echo ""
echo "To run the server with TLS:"
echo "  TLS_ENABLED=true TLS_CERT=./certs/server.crt TLS_KEY=./certs/server.key DB_PASSWORD=YourPassword go run main.go"
echo ""
echo "Or using flags:"
echo "  go run main.go --tls --tls-cert ./certs/server.crt --tls-key ./certs/server.key --db-password YourPassword"
