# TLS Server for STM32U5 Device Testing

## Build wolfSSL and wolfCLU

```bash
cd ../wolfssl
make clean
./autogen.sh
./configure \
  --enable-harden \
  --enable-wolfclu \
  --enable-ecc \
  --enable-pkcallbacks \
  --enable-keygen \
  --enable-tls13 \
  --enable-mlkem \
  --enable-dilithium \
  --enable-opensslall \
  --enable-ed25519 \
  --enable-certgen \
  --enable-base16 \
  --enable-dual-alg-certs \
  --enable-certreq \
  --enable-pwdbased \
  --enable-experimental
make -j$(nproc)
sudo make install
sudo ldconfig
```

```bash
cd ../wolfCLU
make clean
./autogen.sh
./configure --with-wolfssl=/usr/local \
  CFLAGS="-g -O2 -Wno-error" \
  CPPFLAGS="-DOPENSSL_ALL -DHAVE_BASE16 -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_REQ -DWOLFSSL_PWDBASED"
make -j$(nproc)
sudo make install
```

## Build Server

```bash
cd tls_usb_test
make clean
make
```

**Verify dual-algorithm support:**
```bash
./test_cert_loading
```

You should see "✓ Dilithium key loaded" and "✓ Dual-algorithm keys loaded". If you see "WOLFSSL_DUAL_ALG_CERTS not enabled in this build", rebuild wolfSSL as shown above.

## Generate Hybrid Certificate (ECC + Dilithium)

```bash
mkdir -p certs

# 1. Generate ECC P-384 Key (Changed from prime256v1 to secp384r1)
openssl ecparam -genkey -name secp384r1 -out certs/ecc-server-key.pem

# 2. Generate Dilithium Level 3 Key (Unchanged)
wolfssl -genkey dilithium -level 3 \
  -out certs/dilithium-server \
  -outform pem \
  -output keypair

# 3. Create ECC P-384 Certificate 
# (Changed -sha256 to -sha384 to match the P-384 security level)
openssl req -new -x509 -key certs/ecc-server-key.pem \
  -out certs/ecc-server-cert.pem \
  -days 365 -nodes \
  -sha384 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# 4. Create Dual-Algorithm (Hybrid) Certificate
# This injects the Dilithium public key into the P-384 certificate extensions
wolfssl ca -altextend \
  -in certs/ecc-server-cert.pem \
  -keyfile certs/ecc-server-key.pem \
  -altkey certs/dilithium-server.priv \
  -altpub certs/dilithium-server.pub \
  -out certs/server-cert-hybrid.pem
```

## Run Server
```bash
./tls_server 11111 \
  certs/server-cert-hybrid.pem \
  certs/ecc-server-key.pem \
  certs/dilithium-server.priv
```

## Generate Client Certificates (for Mutual TLS)

### Client Hybrid Certificate (ECC + Dilithium)

```bash
# Generate ECC key
openssl ecparam -genkey -name prime256v1 -out certs/client-key.pem

# Generate Dilithium key
wolfssl -genkey dilithium -level 3 \
  -out certs/client-dilithium \
  -outform pem \
  -output keypair

# Create ECC certificate (explicitly use SHA256 - TLS 1.3 requires SHA256 or better)
openssl req -new -x509 -key certs/client-key.pem \
  -out certs/client-cert-ecc.pem \
  -days 365 -nodes \
  -sha256 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=client-device"

# Create dual-algorithm certificate
wolfssl ca -altextend \
  -in certs/client-cert-ecc.pem \
  -keyfile certs/client-key.pem \
  -altkey certs/client-dilithium.priv \
  -altpub certs/client-dilithium.pub \
  -out certs/client-cert.pem

# Embed certificates in firmware
./embed_client_certs.sh \
  certs/client-cert.pem \
  certs/client-key.pem \
  certs/client-dilithium.priv \
  ../app/client_certs.h
```
The helper script now also defines `CLIENT_DILITHIUM_KEY_LEVEL` inside `app/client_certs.h`. It derives the level from the Dilithium PEM header or the `CLIENT_DILITHIUM_LEVEL` environment variable. When providing a Dilithium key that's already in DER format, export the level explicitly before running the script, for example:

```bash
CLIENT_DILITHIUM_LEVEL=5 ./embed_client_certs.sh \
  certs/client-cert.pem certs/client-key.pem certs/client-dilithium.der \
  ../app/client_certs.h
```

## Test Connection

Terminal 1:
```bash
./tls_server
```

Terminal 2:
```bash
python3 usb_tcp_bridge.py /dev/ttyACM0 localhost 11111
# Type: TLS
```

### Debugging TLS Handshake Issues

The bridge now supports verbose TLS handshake logging to help debug connection issues:

1. Start the bridge as shown above
2. Type `debug` or `log` to enable verbose logging
3. Type `TLS` to start the handshake
4. The bridge will show detailed information about:
   - ClientHello and ServerHello messages
   - Cipher suites offered and selected
   - Supported groups (key exchange algorithms)
   - Signature algorithms
   - Extensions
   - Alert messages (with special attention to illegal_parameter)

Example:
```bash
> debug
[BRIDGE] Verbose TLS debugging enabled
> TLS
[USB->TCP] TLS Handshake: client_hello (len=...)
  Cipher Suites: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256
  Extensions:
    supported_groups: ML-KEM-768, secp256r1
    signature_algorithms: ecdsa_secp256r1_sha256, dilithium3
    ...
```

Type `debug off` to disable verbose logging.

### Troubleshooting Dual-Algorithm Signatures

- **`Dilithium import failed (-173)` / `Dual sign failure at 'Dilithium import'`:** Use `wc_Dilithium_PrivateKeyDecode()` on the embedded PKCS#8 buffer instead of `wc_dilithium_import_private()`. The decoder auto-detects the key level (or validates the level you set via `wc_dilithium_set_level()`). Regenerate `app/client_certs.h` if you changed the key material, rebuild, and ensure SYSTEM and host tests link against a wolfSSL build that includes Dilithium support.
