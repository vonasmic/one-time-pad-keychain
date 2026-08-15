# QKD (ETSI 014) certificates for `Qkd014Client`

QKD mTLS uses **HSM-backed** SAE client keys (Utimaco CryptoServer JCE). Private keys are **not** loaded from PKCS#12 at runtime.

`CertGenerator` handles both this import (option 2) and the unrelated internal PQC node certs
(`certs/Alice.pem`, etc., option 1/3) used by RMI/TLS — see the main
[`JAVA_TLS_TEST/README.md`](../../README.md).

## Target layout

```text
JAVA_TLS_TEST/certs/qkd/
  qkd-server-ca.p12     # trust anchor for the KME server (public CA only)
  # sae-*-client.p12    # temporary — import into HSM, then delete
```

HSM keystore aliases (after import): `sae-1`, `sae-2`, …

## Step 1 — Generate QuKayDee client PEM files

From the repo (requires `openssl`):

```bash
cd ../../QKD/qukaydee-generate-client-certificates

./generate-client-root-ca-certificate-and-key.sh
./generate-client-sae-certificate-and-key.sh sae-1
./generate-client-sae-certificate-and-key.sh sae-2
```

Upload `client-root-ca.crt` to QuKayDee (API → Upload Client CA Certificate).

## Step 2 — Download KME server CA from QuKayDee

API → Download Server CA Certificate → save next to the scripts, e.g.
`account-${ACCOUNT_ID}-server-ca-qukaydee-com.crt`

## Step 3 — Build temporary PKCS#12 + truststore

From **`JAVA_TLS_TEST`**:

```bash
mkdir -p certs/qkd
export ACCOUNT_ID=your-account-id-here
PEM_DIR=../QKD/qukaydee-generate-client-certificates
PASS=password
SERVER_CA="$PEM_DIR/account-${ACCOUNT_ID}-server-ca-qukaydee-com.crt"

for SAE in sae-1 sae-2; do
  openssl pkcs12 -export \
    -inkey "$PEM_DIR/$SAE.key" \
    -in "$PEM_DIR/$SAE.crt" \
    -certfile "$PEM_DIR/client-root-ca.crt" \
    -out "certs/qkd/$SAE-client.p12" \
    -name sae-client \
    -passout pass:$PASS
done

rm -f certs/qkd/qkd-server-ca.p12
keytool -importcert -noprompt \
  -alias qkd-server-ca \
  -file "$SERVER_CA" \
  -keystore certs/qkd/qkd-server-ca.p12 \
  -storetype PKCS12 \
  -storepass "$PASS"
```

## Step 4 — Import SAE keys into HSM (CertGenerator)

Simulator running, `env/hsm.env` sourced:

```bash
set -a && source env/hsm.env && set +a
mvn -q exec:java -Dexec.mainClass=fel.cvut.certGen.CertGenerator
# choose 2) Import QuKayDee SAE PKCS#12 into HSM
# alias sae-1 → certs/qkd/sae-1-client.p12 (repeat for sae-2)
# password prompt [password] if using the default PASS from step 3
```

CertGenerator can delete the PKCS#12 after import. Runtime signing uses CryptoServer only.
## Step 5 — Env / node config

```bash
QKD_HSM_KEY_ALIAS=sae-1          # this node's SAE alias in the HSM
QKD_TRUSTSTORE_PATH=certs/qkd/qkd-server-ca.p12
QKD_TRUSTSTORE_PASSWORD=password
```

## Step 6 — Run demo

```bash
set -a && source env/hsm.env && set +a
mvn -q compile exec:java -Dexec.mainClass=fel.cvut.qkd.Qkd014Demo \
  -Dqkd.baseUrl=https://kme-1.<acct>.etsi-qkd-api.qukaydee.com \
  -Dqkd.masterHsmAlias=sae-1 \
  -Dqkd.slaveHsmAlias=sae-2 \
  -Dqkd.truststore=certs/qkd/qkd-server-ca.p12
```

| Step | Method | KME host | HSM alias | URL path |
|------|--------|----------|-----------|----------|
| Get key | `enc_keys` | **kme-1** | sae-1 | `/api/v1/keys/sae-2/enc_keys` |
| Get key with key IDs | `dec_keys` | **kme-2** | sae-2 | `/api/v1/keys/sae-1/dec_keys?key_ID=...` |

## What lives where

| Material | Location |
|----------|----------|
| SAE client private key | HSM CryptoServer keystore (`QKD_HSM_KEY_ALIAS`) |
| SAE client cert chain | HSM (stored with the key at import) |
| KME server CA | `certs/qkd/qkd-server-ca.p12` (trust only) |
