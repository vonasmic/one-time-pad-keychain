# CertGenerator

Non-interactive PKI / HSM provisioner for SAE nodes and UserApp bundles. There is no menu: one run
creates anything still missing and leaves existing material alone.

Working directory must be `JAVA_TLS_TEST` (so `certs/` and `env/` resolve).

## Prerequisites

- Java 21 and Maven (run from `JAVA_TLS_TEST`)
- Utimaco vendor tree: `vendor/pqmi-java/`, `vendor/securityserver-jce.jar`, `vendor/cryptoservercxi.jar`
- `env/hsm.env` sourced for a full run (node keys + QuKayDee import)
- HSM simulator or cHSM up — one-time init is in the
  [JAVA_TLS_TEST README — HSM setup](../../README.md#hsm-setup)
- Software CAs and client certs do **not** need a live HSM

## What it does

Each run, in order:

1. **Root CA** (`CERTGEN_ROOT_CA`) — load `certs/ca/{name}.p12` if present, otherwise generate
   a new software ML-DSA CA. Always writes `certs/ca/{name}.pem`.
2. **Client CA** (`CERTGEN_CLIENT_CA`) — same, also under `certs/ca/`.
3. **Node identities** (`CERTGEN_NODES`) — for each name:
   - if the PQMI ML-DSA key is missing, generate it **inside the HSM** (non-exportable);
   - if the leaf PEM is missing (or a new key was just created), export the public key and
     issue `certs/{Name}.pem` signed by the root CA.
   - if both the HSM key and PEM already exist, skip — unless the PEM is not signed by the
     current root CA, which re-issues it from the HSM public key.
4. **Software client bundles** (`CERTGEN_CLIENTS`) — ML-DSA key + cert signed by the client
   CA, only when the bundle files are missing. Trust is `certs/ca/{CERTGEN_CLIENT_CA}.pem`
   (not copied into the client folder). If an existing cert is not signed by the current
   client CA, it is re-signed in place and the key is kept so the device `client_hash`
   does not move.
   Incomplete pairs (cert without key, or the reverse) fail the run.
5. **QuKayDee SAE keys** — import every `certs/qkd/*-client.p12` whose CryptoServer alias
   is not already present. Those keys are **not** generated in the HSM. If the directory or
   files are absent, this step is skipped. PKCS#12 files are left on disk.

The node process never creates HSM keys. After an HSM reinit, run CertGenerator again.

If the HSM is down (`NO_CONNECTION` / refused / missing `HSM_*` env), the run still
creates **software** material (root CA, client CA, client bundles) and skips node keys
and QuKayDee import.

## Source layout

```text
src/CertGenerator/
  README.md
  main/java/fel/cvut/certGen/   CertGenerator, CertGenConfig, HsmKeyImporter
  test/java/fel/cvut/certGen/   HSM-unreachable fallback tests
```

TLS / HSM helpers used here live in [SaeNode](../SaeNode/README.md) (`fel.cvut.tls`, `fel.cvut.utimaco`).

## How to run

```bash
cd JAVA_TLS_TEST
cp env/example/hsm.env.example env/hsm.env          # once; do not commit the PIN
cp env/example/certgen.env.example env/certgen.env  # once; edit names as needed

set -a && source env/hsm.env && set +a
mvn exec:java -Dexec.mainClass=fel.cvut.certGen.CertGenerator
```

`env/certgen.env` is read from disk by the process. `env/hsm.env` must be **sourced**
(Java cannot see that file unless the variables are in the environment).

Optional: `CERTGEN_ENV=/path/to/file` selects a different certgen env file.

Already-exported variables override values from the certgen file.

If the device client bundle was created or replaced, enroll it on the device with
USB `OWNER SET` (unsigned blob may include device cert/key and SAE CA). Firmware does
not compile client certs in. CREDS SAE / CREDS DEVICE are unsigned MANAGE TLS commands.

QuKayDee PKCS#12 build steps (openssl / keytool) are in [`certs/qkd/README.md`](../../certs/qkd/README.md).
CertGenerator only imports files that are already there.

## Config — `env/certgen.env`

Template: [`env/example/certgen.env.example`](../../env/example/certgen.env.example).

Names are basenames (no path, `.pem` / `.p12` suffix is stripped if present).
CAs live in `certs/ca/`, so `certs/*.pem` is only node leaves. Root CA and client CA names must differ.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `CERTGEN_ROOT_CA` | no | `root-ca` | SAE trust-anchor basename → `certs/ca/{name}.p12` + `.pem`. |
| `CERTGEN_CLIENT_CA` | no | `client_ca` | Client-auth CA basename → `certs/ca/{name}.p12` + `.pem`. |
| `CERTGEN_NODES` | **yes** | — | Node leaf CNs / HSM key names / `certs/{Name}.pem`. Example: `Alice,Bob,Carol,Terminal`. |
| `CERTGEN_CLIENTS` | no | empty | Software ML-DSA client CNs. Empty means no client bundles. |
| `CERTGEN_ENV` | no | `env/certgen.env` | Path to the certgen env file (process environment only, not inside the file). |

`Alice` / `ALICE` / `alice` are stored as `Alice` (same for Bob / Carol) so they match
`TLS_NODE_ID` at runtime.

### Client output paths

| `CERTGEN_CLIENTS` entry | Files written |
| --- | --- |
| `native-tls-client` | `certs/client/client-cert.pem`, `certs/client/client-key.pem` |
| `native-tls-client-2` | `certs/client2/client-cert.pem`, `certs/client2/client-key.pem` |
| `otp-user` | `certs/user/user-cert.pem`, `certs/user/user-key.pem` |
| any other CN | `certs/clients/{cn}/{cn}-cert.pem`, `{cn}-key.pem` |

### QuKayDee (no extra certgen variables)

- Looks in `certs/qkd/` for `*-client.p12` (alias = filename without `-client.p12`, e.g. `sae-1-client.p12` → HSM alias `sae-1`).
- PKCS#12 password is `password` (same as the qkd README openssl `-passout`).
- Skips aliases already in the CryptoServer keystore.
- Runtime uses `QKD_HSM_KEY_ALIAS` in the node env file; that is not a CertGenerator input.

## Config — HSM (`env/hsm.env`, must be sourced)

Template: [`env/example/hsm.env.example`](../../env/example/hsm.env.example).
All of these are required (`Pqmi.fromEnvironment`).

| Variable | Example | Meaning |
| --- | --- | --- |
| `HSM_DEVICE` | `3001@127.0.0.1` | Simulator / cHSM address |
| `HSM_TIMEOUT_MS` | `60000` | CXI timeout |
| `HSM_USER` | `CXI_HMAC` | HSM user |
| `HSM_PIN` | *(local only)* | User PIN |
| `HSM_MLDSA_GROUP` | `JAVA_TLS_TEST` | PQMI key group; node keys live at `{group}/{Node}` |
| `HSM_MLDSA_SPEC` | `0` | PQMI key spec |

## What is not generated here

| Material | Where it lives | Notes |
| --- | --- | --- |
| Node ML-DSA private keys | HSM (PQMI) | Born in the HSM; only the public key / PEM leave |
| Root / client CA private keys | `certs/ca/{name}.p12` (password `password`) | Software PKCS#12 |
| Device / user ML-DSA private keys | PEM under `certs/client/` or `certs/user/` | Software; not HSM |
| QuKayDee SAE private keys | CryptoServer after import | Generated by openssl / QuKayDee scripts, then imported |
| KME server CA truststore | `certs/qkd/qkd-server-ca.p12` | Public only; not created by CertGenerator |

## Layout after a default run

```text
certs/
  ca/
    root-ca.p12        root-ca.pem
    client_ca.p12      client_ca.pem
  Alice.pem            Bob.pem  Carol.pem  Terminal.pem
  client/client-cert.pem   client/client-key.pem
  client2/client-cert.pem  client2/client-key.pem
  user/user-cert.pem       user/user-key.pem
  qkd/*-client.p12     # imported if present; not deleted
```
