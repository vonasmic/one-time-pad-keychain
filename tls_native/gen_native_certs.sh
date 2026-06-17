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
"$WOLFSSL" ca -help 2>&1 | grep -q "altextend" || die "wolfCLU needs ca -altextend (dual-alg certs)"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$SERVER_DIR" "$CLIENT_DIR"

make_chimera_ca() {
    local prefix="$1"
    local cn="$2"
    local ca_dir="$WORK_DIR/$prefix-ca"

    mkdir -p "$ca_dir"

    openssl ecparam -genkey -name secp384r1 -out "$ca_dir/ecc-ca-key.pem"
    "$WOLFSSL" -genkey dilithium -level 3 \
        -out "$ca_dir/dilithium-ca" \
        -outform pem \
        -output keypair
    openssl req -new -x509 -key "$ca_dir/ecc-ca-key.pem" \
        -out "$ca_dir/ca-cert.pem" \
        -days 365 -nodes \
        -sha384 \
        -addext "basicConstraints = critical, CA:TRUE" \
        -addext "keyUsage = critical, keyCertSign, cRLSign" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$cn"
    "$WOLFSSL" ca -altextend \
        -in "$ca_dir/ca-cert.pem" \
        -keyfile "$ca_dir/ecc-ca-key.pem" \
        -altkey "$ca_dir/dilithium-ca.priv" \
        -altpub "$ca_dir/dilithium-ca.pub" \
        -out "$ca_dir/ca-cert-hybrid.pem"
}

make_signed_identity() {
    local leaf_id="$1"
    local leaf_cn="$2"
    local leaf_out_dir="$3"
    local ca_prefix="$4"
    local key_basename="$5"
    local dilithium_basename="$6"

    local leaf_dir="$WORK_DIR/$leaf_id"
    local ca_dir="$WORK_DIR/$ca_prefix-ca"
    mkdir -p "$leaf_dir" "$leaf_out_dir"

    # wolfSSL TLS hybrid sig IDs are fixed pairs (see HYBRID_*_SA_MINOR in tls13.c):
    # P-256 + Dilithium-2, P-384 + Dilithium-3, P-521 + Dilithium-5.
    # P-256 + Dilithium-3 is not a valid combination for CKS BOTH handshakes.
    openssl ecparam -genkey -name secp384r1 -out "$leaf_dir/ecc-key.pem"
    "$WOLFSSL" -genkey dilithium -level 3 \
        -out "$leaf_dir/dilithium" \
        -outform pem \
        -output keypair

    openssl req -new -key "$leaf_dir/ecc-key.pem" \
        -out "$leaf_dir/leaf.csr" \
        -sha384 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$leaf_cn"
    "$WOLFSSL" ca \
        -in "$leaf_dir/leaf.csr" \
        -keyfile "$ca_dir/ecc-ca-key.pem" \
        -cert "$ca_dir/ca-cert.pem" \
        -out "$leaf_dir/leaf-cert.pem"
    "$WOLFSSL" ca -altextend \
        -in "$leaf_dir/leaf-cert.pem" \
        -keyfile "$ca_dir/ecc-ca-key.pem" \
        -altkey "$ca_dir/dilithium-ca.priv" \
        -altpub "$leaf_dir/dilithium.pub" \
        -subjkey "$leaf_dir/ecc-key.pem" \
        -cert "$ca_dir/ca-cert-hybrid.pem" \
        -out "$leaf_out_dir/server-cert-hybrid.pem"

    install -m 0644 "$leaf_dir/ecc-key.pem" "$leaf_out_dir/$key_basename"
    install -m 0644 "$leaf_dir/dilithium.priv" "$leaf_out_dir/$dilithium_basename"
}

echo "[*] Creating CA hierarchy..."
make_chimera_ca "server" "native-server-root-ca"
make_chimera_ca "client" "native-client-root-ca"

echo "[*] Creating server identity signed by server CA..."
make_signed_identity \
    "server-leaf" "jni-server" "$SERVER_DIR" "server" \
    "ecc-server-key.pem" "dilithium-server.priv"

echo "[*] Creating client identities signed by client CA..."
for client_id in client-1 client-2 client-3; do
    make_signed_identity \
        "$client_id-leaf" "tls-$client_id" "$CLIENT_DIR/$client_id" "client" \
        "ecc-server-key.pem" "dilithium-server.priv"
done

echo "[*] Installing trust anchors..."
install -m 0644 "$WORK_DIR/client-ca/ca-cert-hybrid.pem" "$SERVER_DIR/root-ca.pem"
for client_id in client-1 client-2 client-3; do
    install -m 0644 "$WORK_DIR/server-ca/ca-cert-hybrid.pem" "$CLIENT_DIR/$client_id/root-ca.pem"
done

rm -rf "$WORK_DIR"

echo "[+] $SERVER_DIR/"
echo "    server-cert-hybrid.pem  ecc-server-key.pem  dilithium-server.priv  root-ca.pem"
echo "[+] $CLIENT_DIR/"
echo "    client-1/ client-2/ client-3/ (each has server-cert-hybrid.pem, ecc-server-key.pem, dilithium-server.priv, root-ca.pem)"
