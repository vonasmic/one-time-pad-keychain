#!/bin/bash
# Verify that a certificate file has dual-algorithm signatures
#
# Usage: ./verify_hybrid_cert.sh <cert_file>

CERT_FILE="${1:-certs/server-cert-hybrid.pem}"

if [ ! -f "$CERT_FILE" ]; then
    echo "Error: Certificate file not found: $CERT_FILE"
    exit 1
fi

echo "Verifying certificate: $CERT_FILE"
echo ""

# Check if certificate can be read
echo "1. Checking certificate format..."
if openssl x509 -in "$CERT_FILE" -text -noout > /dev/null 2>&1; then
    echo "   ✓ Certificate is valid PEM format"
else
    echo "   ✗ Certificate is not valid PEM format"
    exit 1
fi

# Check for signature algorithm
echo ""
echo "2. Checking signature algorithm..."
SIG_ALG=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -i "Signature Algorithm" | head -1)
echo "   $SIG_ALG"

# Check for ECDSA signature
if echo "$SIG_ALG" | grep -qi "ecdsa\|ecdsa-with"; then
    echo "   ✓ ECDSA signature found"
    HAS_ECDSA=1
else
    echo "   ✗ ECDSA signature NOT found"
    HAS_ECDSA=0
fi

# Check for Dilithium/ML-DSA signature (in extensions or alternative signature)
echo ""
echo "3. Checking for dual-algorithm extensions..."
if openssl x509 -in "$CERT_FILE" -text -noout | grep -qi "dilithium\|ml-dsa\|alternative.*signature"; then
    echo "   ✓ Dual-algorithm extensions found"
    HAS_DILITHIUM=1
else
    echo "   ⚠ Dual-algorithm extensions not found in text output"
    echo "   Note: wolfSSL's dual-algorithm certificates may not show in standard openssl output"
    HAS_DILITHIUM=0
fi

# Try to verify with wolfssl if available
echo ""
echo "4. Verifying with wolfssl (if available)..."
if command -v wolfssl &> /dev/null; then
    WOLFSSL_OUTPUT=$(wolfssl x509 -in "$CERT_FILE" -text -noout 2>&1)
    if echo "$WOLFSSL_OUTPUT" | grep -qi "dilithium\|ml-dsa\|alternative"; then
        echo "   ✓ wolfSSL detects dual-algorithm certificate"
        HAS_DILITHIUM=1
    else
        echo "   ⚠ wolfSSL output doesn't explicitly show dual-algorithm signatures"
        echo "   Full wolfSSL output:"
        echo "$WOLFSSL_OUTPUT" | head -20 | sed 's/^/      /'
    fi
    
    # Try to verify the certificate can be loaded with dual-algorithm support
    echo ""
    echo "5. Testing certificate loading with wolfSSL..."
    if wolfssl verify -CAfile "$CERT_FILE" -check_ss_sig "$CERT_FILE" 2>&1 | grep -qi "ok\|verify return code: 0"; then
        echo "   ✓ Certificate can be verified by wolfSSL"
    else
        echo "   ⚠ Certificate verification test (this is expected for self-signed certs)"
    fi
else
    echo "   ⚠ wolfssl command not found (skipping wolfSSL verification)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
if [ "$HAS_ECDSA" -eq 1 ]; then
    echo "✓ Certificate has ECDSA signature"
else
    echo "✗ Certificate missing ECDSA signature"
fi

if [ "$HAS_DILITHIUM" -eq 1 ]; then
    echo "✓ Certificate appears to have Dilithium signature (dual-algorithm)"
else
    echo "⚠ Certificate may not have Dilithium signature"
    echo "  If certificate was created with 'wolfssl ca -altextend', it should have both signatures"
    echo "  Standard openssl may not display dual-algorithm extensions"
fi

echo ""
echo "Note: If client rejects with 'illegal_parameter', check client error logs"
echo "      The client will print: 'TLS: Server cert verify failed (err=...)'"
echo "═══════════════════════════════════════════════════════════"

