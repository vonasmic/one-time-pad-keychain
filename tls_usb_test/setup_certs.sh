#!/bin/bash
# Generate server certificate and key for TLS testing

CERT_DIR="certs"
CERT_FILE="$CERT_DIR/server-cert.pem"
KEY_FILE="$CERT_DIR/server-key.pem"

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificate already exists
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "Certificate and key already exist:"
    echo "  Certificate: $CERT_FILE"
    echo "  Private Key: $KEY_FILE"
    echo ""
    read -p "Regenerate? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing certificate."
        exit 0
    fi
    rm -f "$CERT_FILE" "$KEY_FILE"
fi

echo "Generating server certificate and private key..."
echo ""

# Generate certificate with 2048-bit RSA key
openssl req -x509 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
    2>/dev/null

if [ $? -eq 0 ]; then
    echo "✓ Certificate generated successfully!"
    echo ""
    echo "Files created:"
    echo "  Certificate: $CERT_FILE"
    echo "  Private Key: $KEY_FILE"
    echo ""
    echo "Certificate details:"
    openssl x509 -in "$CERT_FILE" -noout -subject -dates
else
    echo "✗ Error generating certificate"
    echo "Make sure OpenSSL is installed: sudo apt-get install openssl"
    exit 1
fi


