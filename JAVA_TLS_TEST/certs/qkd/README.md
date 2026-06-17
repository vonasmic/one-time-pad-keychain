# QKD (ETSI 014) certificates for `Qkd014Client`

`Qkd014Client` expects **two PKCS12 files** in this directory. Generate them with OpenSSL (not `CertGenerator`).

`CertGenerator` is only for internal PQC node certs (`certs/Alice.p12`, etc.) used by RMI/TLS.

## Target layout

After setup you should have:

```text
JAVA_TLS_TEST/certs/qkd/
  sae-1-client.p12      # master SAE identity (calls enc_keys)
  sae-2-client.p12      # slave SAE identity (calls dec_keys)
  qkd-server-ca.p12     # trust anchor for the KME server
```

Default password for both: `password` (must match `-Dqkd.clientKeystorePassword` / `-Dqkd.truststorePassword` if you override them).

## Step 1 — Generate QuKayDee client PEM files

From the repo (requires `openssl`):

```bash
cd ../../QKD/qukaydee-generate-client-certificates

# once per account
./generate-client-root-ca-certificate-and-key.sh

# once per SAE (encryptor), e.g. sae-1
./generate-client-sae-certificate-and-key.sh sae-1
```

This creates in that folder:

- `client-root-ca.crt` — upload to QuKayDee (API → Upload Client CA Certificate)
- `sae-1.crt`, `sae-1.key` — your SAE client certificate and key

## Step 2 — Download KME server CA from QuKayDee

In the QuKayDee UI: **API → Download Server CA Certificate**.

Save the file next to the scripts. The filename includes your account ID, e.g.:

`QKD/qukaydee-generate-client-certificates/account-${ACCOUNT_ID}-server-ca-qukaydee-com.crt`

## Step 3 — Convert PEM → PKCS12

Run these commands from the **`JAVA_TLS_TEST`** directory (the folder that contains `pom.xml`):

```bash
cd ~/diplomka/one-time-pad-keychain/JAVA_TLS_TEST
mkdir -p certs/qkd

export ACCOUNT_ID=your-account-id-here
PEM_DIR=../QKD/qukaydee-generate-client-certificates
SAE=sae-1
PASS=password
SERVER_CA="$PEM_DIR/account-${ACCOUNT_ID}-server-ca-qukaydee-com.crt"

# Client keystores (mTLS identity) — one per SAE; OpenSSL is fine here
for SAE in sae-1 sae-2; do
  openssl pkcs12 -export \
    -inkey "$PEM_DIR/$SAE.key" \
    -in "$PEM_DIR/$SAE.crt" \
    -certfile "$PEM_DIR/client-root-ca.crt" \
    -out "certs/qkd/$SAE-client.p12" \
    -name sae-client \
    -passout pass:$PASS
done

# Truststore (KME server CA only) — use keytool, NOT openssl pkcs12 -export -nokeys
# (OpenSSL cert-only PKCS#12 has 0 entries in Java/BC and breaks TLS trust validation)
rm -f certs/qkd/qkd-server-ca.p12
keytool -importcert -noprompt \
  -alias qkd-server-ca \
  -file "$SERVER_CA" \
  -keystore certs/qkd/qkd-server-ca.p12 \
  -storetype PKCS12 \
  -storepass "$PASS"
```

Verify both stores:

```bash
keytool -list -keystore certs/qkd/qkd-server-ca.p12 -storepass password
keytool -list -keystore certs/qkd/sae-1-client.p12 -storepass password
keytool -list -keystore certs/qkd/sae-2-client.p12 -storepass password
```

You should see **1 entry** in each keystore. If `keytool` says `alias <qkd-server-ca> already exists`, the truststore is already built — run `keytool -list` only; no need to import again unless you downloaded a new server CA.

## Step 4 — Run the QKD demo

### IntelliJ IDEA

1. **Run → Edit Configurations…** → `Qkd014Demo`
2. **Working directory:** `.../one-time-pad-keychain/JAVA_TLS_TEST` (must contain `certs/qkd/`)
3. **Build** the project before run (so `target/classes` includes the latest demo)
4. Optional **VM options** (or set `QKD_BASE_URL` in env — see `.env.example`):

```text
-Dqkd.baseUrl=https://kme-1.acct-your-account-id-here.etsi-qkd-api.qukaydee.com
-Dqkd.slaveBaseUrl=https://kme-2.acct-your-account-id-here.etsi-qkd-api.qukaydee.com
-Dqkd.masterSaeId=sae-1
-Dqkd.slaveSaeId=sae-2
```

If `qkd.slaveBaseUrl` is omitted, the demo defaults to `kme-2` when `qkd.baseUrl` uses `kme-1` (QuKayDee layout).

### QuKayDee API mapping (same as official curl demo)

| Step | Method | KME host | Client cert | URL path |
|------|--------|----------|-------------|----------|
| Get key | `enc_keys` | **kme-1** | sae-1 | `/api/v1/keys/sae-2/enc_keys` |
| Get key with key IDs | `dec_keys` | **kme-2** | sae-2 | `/api/v1/keys/sae-1/dec_keys?key_ID=...` |

Calling `dec_keys` on **kme-1** with the sae-2 certificate returns `Secure application entity not found` — use **kme-2** for the slave call.

### Maven

```bash
mvn -q compile exec:java -Dexec.mainClass=fel.cvut.qkd.Qkd014Demo \
  -Dqkd.baseUrl=https://kme-1.<your-account>.etsi-qkd-api.qukaydee.com \
  -Dqkd.clientKeystore=certs/qkd/sae-1-client.p12 \
  -Dqkd.slaveClientKeystore=certs/qkd/sae-2-client.p12 \
  -Dqkd.truststore=certs/qkd/qkd-server-ca.p12 \
  -Dqkd.masterSaeId=sae-1 \
  -Dqkd.slaveSaeId=sae-2
```

The demo runs a full ETSI 014 round-trip: **sae-1** on **kme-1** calls `enc_keys`, then **sae-2** on **kme-2** calls `dec_keys` with the returned `key_ID`. Both SAE certs must exist under `certs/qkd/`.

## What each file is for

| File | Role |
|------|------|
| `sae-*-client.p12` | Proves that SAE's identity to the KME (master → `enc_keys`, slave → `dec_keys`) |
| `qkd-server-ca.p12` | Trusts the **KME** server certificate (server CA) |

## PQC `CertGenerator` (separate use case)

For internal node TLS only:

```bash
mvn exec:java -Dexec.mainClass=fel.cvut.certGen.CertGenerator
```

That writes `certs/<NodeName>.p12` — **not** valid for QuKayDee QKD.
