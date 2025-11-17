#!/bin/bash
# Script to convert client certificates to C header file for embedding in firmware
# 
# Usage: ./embed_client_certs.sh <client-cert.pem> <client-key.pem> <client-dilithium-key.pem> [output.h]
#
# This script converts PEM certificates and keys to DER format and then to C arrays
# that can be embedded in the firmware.

set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 <client-cert.pem> <client-key.pem> <client-dilithium-key.pem> [output.h]"
    echo ""
    echo "Converts PEM certificates and keys to C header file for embedding in firmware."
    echo ""
    echo "Example:"
    echo "  $0 certs/client-cert.pem certs/client-key.pem certs/client-dilithium-key.pem app/client_certs.h"
    exit 1
fi

CERT_PEM="$1"
KEY_PEM="$2"
DILITHIUM_KEY_PEM="$3"
OUTPUT="${4:-app/client_certs.h}"

# Check if input files exist
if [ ! -f "$CERT_PEM" ]; then
    echo "Error: Certificate file not found: $CERT_PEM"
    exit 1
fi

if [ ! -f "$KEY_PEM" ]; then
    echo "Error: Key file not found: $KEY_PEM"
    exit 1
fi

if [ ! -f "$DILITHIUM_KEY_PEM" ]; then
    echo "Error: Dilithium key file not found: $DILITHIUM_KEY_PEM"
    exit 1
fi

# Create temporary directory with fixed names for xxd
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Determine if Dilithium key is PEM and capture header for level detection
DILITHIUM_PEM_HEADER=$(head -1 "$DILITHIUM_KEY_PEM" 2>/dev/null || true)
if echo "$DILITHIUM_PEM_HEADER" | grep -q "BEGIN"; then
    DILITHIUM_KEY_IS_PEM=1
else
    DILITHIUM_KEY_IS_PEM=0
    DILITHIUM_PEM_HEADER=""
fi

detect_dilithium_level() {
    local level=""
    if [ -n "$CLIENT_DILITHIUM_LEVEL" ]; then
        level="$CLIENT_DILITHIUM_LEVEL"
    elif [ "$DILITHIUM_KEY_IS_PEM" -eq 1 ]; then
        case "$DILITHIUM_PEM_HEADER" in
            *LEVEL5*) level=5 ;;
            *LEVEL3*) level=3 ;;
            *LEVEL2*) level=2 ;;
            *) level="" ;;
        esac
    fi

    case "$level" in
        2|3|5) printf '%s' "$level" ;;
        "") printf '' ;;
        *)
            echo "Warning: Unsupported Dilithium level '$level' (expected 2, 3, or 5). Ignoring hint." >&2
            printf ''
            ;;
    esac
}

CLIENT_DILITHIUM_LEVEL_DEFINE=$(detect_dilithium_level)
if [ -n "$CLIENT_DILITHIUM_LEVEL_DEFINE" ]; then
    echo "Detected Dilithium level: $CLIENT_DILITHIUM_LEVEL_DEFINE"
else
    echo "Warning: Unable to detect Dilithium level automatically. Set CLIENT_DILITHIUM_LEVEL env var if needed."
fi

# Use fixed filenames so xxd generates predictable variable names
CERT_DER="$TMPDIR/client_cert.der"
KEY_DER="$TMPDIR/client_key.der"
DILITHIUM_KEY_DER="$TMPDIR/client_dilithium_key.der"

echo "Converting certificates to DER format..."

# Convert certificate PEM to DER
openssl x509 -in "$CERT_PEM" -outform DER -out "$CERT_DER" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Failed to convert certificate to DER"
    exit 1
fi

# Convert ECC key PEM to DER
openssl ec -in "$KEY_PEM" -outform DER -out "$KEY_DER" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Failed to convert ECC key to DER"
    exit 1
fi

# For Dilithium key, convert PEM to DER if necessary
if [ "$DILITHIUM_KEY_IS_PEM" -eq 1 ]; then
    echo "Converting Dilithium PEM to DER format..."
    python3 - <<'PY' "$DILITHIUM_KEY_PEM" "$DILITHIUM_KEY_DER"
import base64, sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, "r") as fin:
    lines = [line.strip() for line in fin]
body = "".join(line for line in lines if line and not line.startswith("-----"))
with open(dst, "wb") as fout:
    fout.write(base64.b64decode(body))
PY
else
    cp "$DILITHIUM_KEY_PEM" "$DILITHIUM_KEY_DER"
    echo "Dilithium key already in DER format or assumed ready"
fi

echo "Converting files to C arrays..."

# Generate C header file
cat > "$OUTPUT" << 'EOF'
#ifndef CLIENT_CERTS_H
#define CLIENT_CERTS_H

/* Embedded client certificate and keys for mutual TLS (mTLS)
 * 
 * These certificates are compiled into the firmware.
 * Generated automatically by embed_client_certs.sh
 * DO NOT EDIT MANUALLY - regenerate using the script instead.
 */

#ifdef WOLFSSL_DUAL_ALG_CERTS

EOF

if [ -n "$CLIENT_DILITHIUM_LEVEL_DEFINE" ]; then
    echo "#define CLIENT_DILITHIUM_KEY_LEVEL $CLIENT_DILITHIUM_LEVEL_DEFINE" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
fi

# Convert certificate DER to C array with proper variable names
echo "/* Client certificate (dual-algorithm: ECDSA + Dilithium) in DER format */" >> "$OUTPUT"
xxd -i "$CERT_DER" | sed -E 's/unsigned char [^[]+\[/static const unsigned char client_cert_der[/' | \
    sed -E 's/unsigned int [^;]+_len/static const unsigned int client_cert_der_len/' >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Convert ECC key DER to C array with proper variable names
echo "/* Client ECC private key in DER format */" >> "$OUTPUT"
xxd -i "$KEY_DER" | sed -E 's/unsigned char [^[]+\[/static const unsigned char client_key_der[/' | \
    sed -E 's/unsigned int [^;]+_len/static const unsigned int client_key_der_len/' >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Convert Dilithium key to C array with proper variable names
# Check if it's PEM format (for wolfSSL compatibility)
if [ "$DILITHIUM_KEY_IS_PEM" -eq 1 ]; then
    echo "/* Client Dilithium private key in PEM format (for wolfSSL) */" >> "$OUTPUT"
else
    echo "/* Client Dilithium private key in DER format */" >> "$OUTPUT"
fi
xxd -i "$DILITHIUM_KEY_DER" | sed -E 's/unsigned char [^[]+\[/static const unsigned char client_dilithium_key_der[/' | \
    sed -E 's/unsigned int [^;]+_len/static const unsigned int client_dilithium_key_der_len/' >> "$OUTPUT"

cat >> "$OUTPUT" << 'EOF'

#else
/* WOLFSSL_DUAL_ALG_CERTS not enabled - certificates not needed */
#endif /* WOLFSSL_DUAL_ALG_CERTS */

#endif /* CLIENT_CERTS_H */
EOF

echo ""
echo "✓ Successfully generated embedded certificate header: $OUTPUT"
echo ""
echo "Certificate sizes:"
echo "  Certificate: $(stat -f%z "$CERT_DER" 2>/dev/null || stat -c%s "$CERT_DER") bytes"
echo "  ECC Key: $(stat -f%z "$KEY_DER" 2>/dev/null || stat -c%s "$KEY_DER") bytes"
echo "  Dilithium Key: $(stat -f%z "$DILITHIUM_KEY_DER" 2>/dev/null || stat -c%s "$DILITHIUM_KEY_DER") bytes"
echo ""
echo "Next steps:"
echo "  1. Include client_certs.h in tls_pqc.c"
echo "  2. Load certificates using wolfSSL_CTX_use_certificate_buffer()"
echo "  3. Load keys using wolfSSL_CTX_use_PrivateKey_buffer() and wolfSSL_CTX_use_AltPrivateKey_buffer()"

