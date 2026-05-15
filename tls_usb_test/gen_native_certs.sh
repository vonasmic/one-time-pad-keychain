#!/usr/bin/env bash
# wolfCLU dual-alt PEM bundles for JAVA_TLS_TEST/certs/native/{server,client}.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NATIVE_ROOT_REL="$SCRIPT_DIR/../JAVA_TLS_TEST/certs/native"
mkdir -p "$NATIVE_ROOT_REL/server" "$NATIVE_ROOT_REL/client"
NATIVE_ROOT="$(cd "$NATIVE_ROOT_REL" && pwd)"
SERVER_DIR="$NATIVE_ROOT/server"
CLIENT_DIR="$NATIVE_ROOT/client"
WORK_DIR="$SCRIPT_DIR/.certgen-work"

WOLFSSL="${WOLFSSL:-wolfssl}"

die() { echo "error: $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v "$WOLFSSL" >/dev/null 2>&1 || die "'$WOLFSSL' not found (build wolfCLU; see README)"
"$WOLFSSL" ca -help 2>&1 | grep -q altextend || die "wolfCLU needs ca -altextend (dual-alg certs)"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$SERVER_DIR" "$CLIENT_DIR"

gen_server_bundle() {
    echo "[*] Server: ECC P-384 key..."
    openssl ecparam -genkey -name secp384r1 -out "$WORK_DIR/ecc-server-key.pem"

    echo "[*] Server: Dilithium key (level 3)..."
    "$WOLFSSL" -genkey dilithium -level 3 \
        -out "$WORK_DIR/dilithium-server" \
        -outform pem \
        -output keypair

    echo "[*] Server: ECC certificate..."
    openssl req -new -x509 -key "$WORK_DIR/ecc-server-key.pem" \
        -out "$WORK_DIR/ecc-server-cert.pem" \
        -days 365 -nodes \
        -sha384 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=jni-server"

    echo "[*] Server: dual-algorithm certificate..."
    "$WOLFSSL" ca -altextend \
        -in "$WORK_DIR/ecc-server-cert.pem" \
        -keyfile "$WORK_DIR/ecc-server-key.pem" \
        -altkey "$WORK_DIR/dilithium-server.priv" \
        -altpub "$WORK_DIR/dilithium-server.pub" \
        -out "$SERVER_DIR/server-cert-hybrid.pem"

    install -m 0644 "$WORK_DIR/ecc-server-key.pem" "$SERVER_DIR/ecc-server-key.pem"
    install -m 0644 "$WORK_DIR/dilithium-server.priv" "$SERVER_DIR/dilithium-server.priv"
}

gen_client_bundle() {
    # wolfSSL TLS hybrid sig IDs are fixed pairs (see HYBRID_*_SA_MINOR in tls13.c):
    # P-256 + Dilithium-2, P-384 + Dilithium-3, P-521 + Dilithium-5.
    # P-256 + Dilithium-3 is not a valid combination for CKS BOTH handshakes.
    echo "[*] Client: ECC P-384 key..."
    openssl ecparam -genkey -name secp384r1 -out "$WORK_DIR/ecc-server-key.pem"

    echo "[*] Client: Dilithium key (level 3)..."
    "$WOLFSSL" -genkey dilithium -level 3 \
        -out "$WORK_DIR/dilithium-server" \
        -outform pem \
        -output keypair

    echo "[*] Client: ECC certificate..."
    openssl req -new -x509 -key "$WORK_DIR/ecc-server-key.pem" \
        -out "$WORK_DIR/ecc-server-cert.pem" \
        -days 365 -nodes \
        -sha384 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=tls-client"

    echo "[*] Client: dual-algorithm certificate..."
    "$WOLFSSL" ca -altextend \
        -in "$WORK_DIR/ecc-server-cert.pem" \
        -keyfile "$WORK_DIR/ecc-server-key.pem" \
        -altkey "$WORK_DIR/dilithium-server.priv" \
        -altpub "$WORK_DIR/dilithium-server.pub" \
        -out "$CLIENT_DIR/server-cert-hybrid.pem"

    install -m 0644 "$WORK_DIR/ecc-server-key.pem" "$CLIENT_DIR/ecc-server-key.pem"
    install -m 0644 "$WORK_DIR/dilithium-server.priv" "$CLIENT_DIR/dilithium-server.priv"
}

gen_server_bundle
gen_client_bundle

echo "[*] Peer trust anchors (self-signed mTLS)..."
install -m 0644 "$CLIENT_DIR/server-cert-hybrid.pem" "$SERVER_DIR/root-ca.pem"
install -m 0644 "$SERVER_DIR/server-cert-hybrid.pem" "$CLIENT_DIR/root-ca.pem"

rm -rf "$WORK_DIR"

echo "[+] $SERVER_DIR/"
echo "    server-cert-hybrid.pem  ecc-server-key.pem  dilithium-server.priv  root-ca.pem"
echo "[+] $CLIENT_DIR/"
echo "    server-cert-hybrid.pem  ecc-server-key.pem  dilithium-server.priv  root-ca.pem"
