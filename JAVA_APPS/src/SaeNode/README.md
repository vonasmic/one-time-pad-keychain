# SaeNode

**SAE** node process: inter-node RMI, ETSI 014 QKD client, TLS command server for
device **PROVISION**, terminal gateway, local SQLite record state, and HSM-backed
crypto. This is **not** UserApp. Encrypt / decrypt / manage stay on the **USER**
process ([UserApp](../UserApp/README.md)).

Entry point: `fel.cvut.node.Node`.

Working directory must be `JAVA_APPS` (so `certs/` and `env/` resolve).

## What it does

- Authenticates with an HSM ML-DSA identity (`certs/{TLS_NODE_ID}.pem` + PQMI key)
- Serves **PURE_PQC** TLS to peer nodes (RMI) and to [TerminalBridge](../TerminalBridge/README.md)
- Serves **PURE_PQC** TLS on `NODE_NATIVE_PORT` with `client_ca` trust (device mTLS for **PROVISION** / TerminalBridge USB relay).
- Talks to the QuKayDee KME over **CLASSICAL** mTLS.
- Stores client record state and HSM-encrypted QKD key material in **one SQLite file per node**
- Forwards operator SELECT / CONFIRM / NOTIFY to the terminal app via `TerminalGateway`

The node never creates HSM keys. After an HSM reinit, run [CertGenerator](../CertGenerator/README.md) first.

## Prerequisites

- Java 21 and Maven (run from `JAVA_APPS`)
- Utimaco vendor tree: `vendor/pqmi-java/`, `vendor/securityserver-jce.jar`, `vendor/cryptoservercxi.jar`
- HSM simulator or cHSM up — one-time init is in the
  [JAVA_APPS README — HSM setup](../../README.md#hsm-setup)
- Identities provisioned by CertGenerator (`certs/{TLS_NODE_ID}.pem`, `certs/ca/root-ca.pem`, `certs/ca/client_ca.pem`)
- Local writable path for the SQLite file (e.g. `data/qkd-sae-1.db`; created mode `0600` if missing)
- Flyway migrations applied **before** start (`./migrate.sh` / `./migrate-all.sh`)
- `sae-nodes.json` RMI port must match `NODE_RMI_PORT` for this `SAE_ID`

## How to run

From the repo root (sources `env/hsm.env` and the given node env):

```bash
scripts/java.sh node env/node-1.env
```

Or from `JAVA_APPS`:

```bash
cd JAVA_APPS
cp env/example/hsm.env.example env/hsm.env          # once; do not commit the PIN
cp env/example/.env.example env/node-1.env         # once; edit SAE_ID / ports / DB

mkdir -p data
./migrate.sh env/node-1.env                        # or ./migrate-all.sh

set -a
source env/hsm.env
source env/node-1.env
set +a
mvn -pl :sae-node -am exec:java
```

Source **both** env files — Java only sees process environment variables. `env/hsm.env` is
the shared Utimaco connection; `env/node-N.env` is this node's identity, ports, QKD URL,
and database.

Default `mvn -pl :sae-node exec:java` starts `Node`.

## Config — `env/node-N.env`

Template: [`env/example/.env.example`](../../env/example/.env.example).
Peer list: [`main/resources/sae-nodes.json`](main/resources/sae-nodes.json).

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `SAE_ID` | **yes** | — | Local SAE id; must match an entry in `sae-nodes.json` |
| `NODE_RMI_PORT` | **yes** | — | RMI registry port; must match `sae-nodes.json` for this SAE |
| `NODE_NATIVE_PORT` | **yes** | — | TLS command server (device / TerminalBridge USB relay) |
| `NODE_TERMINAL_PORT` | **yes** | — | TLS terminal gateway (TerminalBridge) |
| `NODE_HOSTNAME` | no | `127.0.0.1` | RMI bind / advertised hostname |
| `TLS_NODE_ID` | **yes** | — | HSM key + leaf `certs/{TLS_NODE_ID}.pem` |
| `QKD_BASE_URL` | **yes** | — | KME ETSI 014 base URL |
| `QKD_HSM_KEY_ALIAS` | **yes** | — | CryptoServer alias imported by CertGenerator |
| `QKD_TRUSTSTORE_PATH` | **yes** | — | KME server CA (`certs/qkd/qkd-server-ca.p12`) |
| `QKD_TRUSTSTORE_PASSWORD` | no* | (stdin) | PKCS#12 password (*or `QKD_KEYSTORE_PASSWORD`; prompted if neither set; **do not set in production env**) |
| `DB_URL` | **yes** | — | SQLite JDBC URL, one file per node (`jdbc:sqlite:data/qkd-sae-N.db`) |
| `RECORD_RETENTION_DAYS` | no | `14` | Refuse / purge rows older than this many days |
| `PQC_CERTS_DIR` | no | `certs` | Certificate directory |

## Config — HSM (`env/hsm.env`, must be sourced)

Template: [`env/example/hsm.env.example`](../../env/example/hsm.env.example).
`HSM_DEVICE` / `HSM_USER` / … are required; `HSM_PIN` uses `EnvSecrets.envOrScan` (stdin if unset).
**In production, leave `HSM_PIN` and QKD store passwords out of env files** — see
[JAVA_APPS README — Secrets](../../README.md#secrets).

| Variable | Example | Meaning |
| --- | --- | --- |
| `HSM_DEVICE` | `3001@127.0.0.1` | Simulator / cHSM address |
| `HSM_TIMEOUT_MS` | `60000` | CXI timeout |
| `HSM_USER` | `CXI_HMAC` | HSM user |
| `HSM_PIN` | *(local only)* | User PIN (stdin if unset; **do not set in production env**) |
| `HSM_MLDSA_GROUP` | `JAVA_APPS` | PQMI key group; node keys live at `{group}/{Node}` |
| `HSM_MLDSA_SPEC` | `0` | PQMI key spec |

## Database

SQLite stores `client_record_state`, HSM-encrypted QKD key material
(`shared_key_material`), and `application_log`. Use **one file per node**. The
file is created with POSIX mode `0600` when missing. WAL + `BEGIN IMMEDIATE`
transactions serialize writers from this process only.

`application_log` receives `fel.cvut` messages at INFO and above, and WARNING
and above from every other logger (including Bouncy Castle and HikariCP). The
same filter is applied to the console. SLF4J is bridged through
`java.util.logging`.

New-share states: `RECORD_SYNCHRONIZATION` (may be taken over by a higher issuing
SAE) → `RECORD_FETCHING_STARTED` after both SAEs synchronize and origin locks
fetch (no higher-SAE takeover; 2-minute stale reclaim) → `RECORD_AVAILABLE`.

On start the node runs a timed thread that deletes rows older than
`RECORD_RETENTION_DAYS` (default 14) immediately and then every 24 hours.
Key material follows via `ON DELETE CASCADE`. Independently of purge, any read
or serve path **refuses** rows older than retention (defense against restoring
an old DB file).

```bash
mkdir -p data
./migrate.sh env/node-1.env     # loads env and runs mvn flyway:migrate
./migrate-all.sh                # every env/node-*.env
```

Flyway scripts live in [`main/resources/db/migration`](main/resources/db/migration).
With env already exported:

```bash
mvn -pl :sae-node flyway:migrate
```

## Source layout

```text
src/SaeNode/
  README.md
  main/java/fel/cvut/node/      Node, bootstrap, TerminalGateway, PeerRecordSync
    interNodeCommunication/     RMI commands
    recordManager/              Client records
  main/java/fel/cvut/db/        JDBC + repositories + RecordRetention
  main/java/fel/cvut/qkd/       ETSI 014 client, Qkd014Demo
  main/java/fel/cvut/se/        Secure-element session / OTP framing
  main/java/fel/cvut/tls/       Shared JSSE / BC / HSM TLS bootstrap
  main/java/fel/cvut/utimaco/   PQMI, HSM gate, AES-GCM
  main/resources/               sae-nodes.json, Flyway SQL
  test/java/                    DB, RMI, HSM, SE, peer-sync tests
```

Operator protocol types (`OperatorConsole`, `TerminalWireProtocol`) live in
[TerminalBridge](../TerminalBridge/README.md). TLS/HSM helpers here are also used by
CertGenerator and TerminalBridge.

## TLS profiles

| Use | Profile | Trust |
| --- | --- | --- |
| Inter-node RMI, terminal gateway | `PURE_PQC` (TLS 1.3 + MLKEM768 + mldsa44) | `certs/ca/root-ca.pem` |
| Command server (`NODE_NATIVE_PORT`) | `PURE_PQC` | `certs/ca/client_ca.pem` (device certs, `PROVISION`) |
| QKD KME mTLS | `CLASSICAL` (prefer TLS 1.3 + MLKEM768 + mldsa44; allow TLS 1.2 + x25519 / classical signatures) | `QKD_TRUSTSTORE_PATH` |

Provider routing is documented in the [JAVA_APPS README](../../README.md#tls).
