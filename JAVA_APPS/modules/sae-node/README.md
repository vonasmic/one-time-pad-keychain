# SaeNode

**SAE** node process: inter-node RMI, ETSI 014 QKD client, USB CDC for device
**PROVISION**, operator stdin (SELECT / CONFIRM / NOTIFY), local SQLite record
state, and HSM-backed crypto. This is **not** UserApp. Encrypt / decrypt / manage
stay on the **USER** process ([UserApp](../user-app/README.md)).

Entry point: `fel.cvut.node.Node`.

Working directory must be `JAVA_APPS` (so `certs/` and `env/` resolve).

## What it does

- Authenticates with an HSM ML-DSA identity (`certs/{name}.pem` + PQMI key, `name` from its [SAE directory](#sae-directory) entry)
- Serves **PURE_PQC** mTLS to peer nodes (RMI): truststore is only the SAE `root-ca`, and every peer leaf must match its `spkiSha384` pin in the [SAE directory](#sae-directory)
- Opens USB CDC and serves **PURE_PQC** TLS with a separate truststore holding only `client_ca` (device mTLS for **PROVISION**)
- Talks to the QuKayDee KME over **CLASSICAL** mTLS.
- Stores client record state and HSM-encrypted QKD key material in **one SQLite file per node**
- Prompts SELECT / CONFIRM / NOTIFY on this process's stdin

The node never creates HSM keys. After an HSM reinit, run [CertGenerator](../cert-generator/README.md) first.

## Prerequisites

- Java 21 and Maven (run from `JAVA_APPS`)
- Utimaco vendor tree: `vendor/pqmi-java/`, `vendor/securityserver-jce.jar`, `vendor/cryptoservercxi.jar`
- HSM simulator or cHSM up — one-time init is in the
  [JAVA_APPS README — HSM setup](../../README.md#hsm-setup)
- Identities provisioned by CertGenerator (`certs/{name}.pem`, `certs/ca/root-ca.pem`, `certs/ca/client_ca.pem`)
- Local writable path for the SQLite file (e.g. `data/qkd-sae-1.db`; created mode `0600` if missing)
- Flyway migrations applied **before** start (`./migrate.sh` / `./migrate-all.sh`)
- The SAE directory `sae-nodes.json` with an entry for this `SAE_ID` whose `spkiSha384` matches
  this node's leaf (see [SAE directory](#sae-directory))

## How to run

From the repo root (sources `env/hsm.env` and the given node env):

```bash
scripts/java.sh node env/node-1.env
```

Or from `JAVA_APPS`:

```bash
cd JAVA_APPS
cp env/example/hsm.env.example env/hsm.env          # once; do not commit the PIN
cp env/example/.env.example env/node-1.env         # once; edit SAE_ID / DB / QKD; set SAE_NODES_FILE

mkdir -p data
./migrate.sh env/node-1.env                        # or ./migrate-all.sh

set -a
source env/hsm.env
source env/node-1.env
set +a
mvn -pl :sae-node -am exec:java
```

Source **both** env files — Java only sees process environment variables. `env/hsm.env` is
the shared Utimaco connection; `env/node-N.env` holds this site's local settings (`SAE_ID`,
directory path, QKD, USB, database). Name, advertised hostname and RMI port come from the
node's entry in the SAE directory.

Default `mvn -pl :sae-node exec:java` starts `Node`.

## Config — `env/node-N.env`

Template: [`env/example/.env.example`](../../env/example/.env.example). The env file holds only
site-local settings; network-wide facts are in the [SAE directory](#sae-directory).

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `SAE_ID` | **yes** | — | Local SAE id; selects this node's entry in the SAE directory. Startup fails if it has none |
| `SAE_NODES_FILE` | **yes** | — | Path of the SAE directory (lab: `env/sae-nodes.json`). Startup fails if unset, unreadable, not a regular file, group- or other-writable, or malformed |
| `NODE_RMI_BIND` | no | own entry's `hostname` | Local interface the RMI registry and object port bind to |
| `USB_SERIAL_PORT` | no | `auto` | CDC path, or `auto` / `scan`; `none` / `off` / `disabled` / `-` skips USB |
| `USB_BAUD_RATE` | no | `115200` | Serial baud rate |
| `QKD_BASE_URL` | **yes** | — | KME ETSI 014 base URL |
| `QKD_HSM_KEY_ALIAS` | **yes** | — | CryptoServer alias imported by CertGenerator |
| `QKD_TRUSTSTORE_PATH` | **yes** | — | KME server CA (`certs/qkd/qkd-server-ca.p12`) |
| `QKD_TRUSTSTORE_PASSWORD` | no* | (prompt) | PKCS#12 password (*or `QKD_KEYSTORE_PASSWORD`; masked terminal prompt if neither is set, startup fails without a terminal; **do not set in production env**) |
| `DB_URL` | **yes** | — | SQLite JDBC URL, one file per node (`jdbc:sqlite:data/qkd-sae-N.db`) |
| `RECORD_RETENTION_DAYS` | no | `14` | Refuse / purge rows older than this many days |
| `APP_LOG` | no | `TERMINAL` | `FULL` sends logs and library prints to stderr. `TERMINAL` prints operator prompts plus one stderr line per WARNING or SEVERE record. Warnings and errors reach the terminal in both modes. SQLite records logs in both modes |
| `PQC_CERTS_DIR` | no | `certs` | Certificate directory |

## Config — HSM (`env/hsm.env`, must be sourced)

Template: [`env/example/hsm.env.example`](../../env/example/hsm.env.example).
`HSM_DEVICE` / `HSM_USER` / … are required; `HSM_PIN` uses `EnvSecrets.envOrScan` (masked terminal prompt if unset; never read from stdin).
**In production, leave `HSM_PIN` and QKD store passwords out of env files** — see
[JAVA_APPS README — Secrets](../../README.md#secrets).

| Variable | Example | Meaning |
| --- | --- | --- |
| `HSM_DEVICE` | `3001@127.0.0.1` | Simulator / cHSM address |
| `HSM_TIMEOUT_MS` | `60000` | CXI timeout |
| `HSM_USER` | `CXI_HMAC` | HSM user |
| `HSM_PIN` | *(local only)* | User PIN (masked terminal prompt if unset; **do not set in production env**) |
| `HSM_MLDSA_GROUP` | `JAVA_APPS` | PQMI key group; node keys live at `{group}/{Node}` |
| `HSM_MLDSA_SPEC` | `0` | PQMI key spec |

## Database

SQLite stores `client_record_state` (including negotiated `pad_plain_len`),
HSM-encrypted QKD key material (`shared_key_material`), and `application_log`.
Use **one file per node**. The
file is created with POSIX mode `0600` when missing. WAL + `BEGIN IMMEDIATE`
transactions serialize writers from this process only.

`application_log` receives `fel.cvut` messages at INFO and above, and WARNING
and above from every other logger (including Bouncy Castle and HikariCP).
That store is written for both `APP_LOG` values. SLF4J is bridged through
`java.util.logging`.

`APP_LOG=FULL` points ordinary stdout at stderr, which is where Java already
writes logs, so debug and Bouncy Castle stay off the prompt stream.
`APP_LOG=TERMINAL` (the default, production) drops that stream and prints
SELECT / CONFIRM / NOTIFY, plus one stderr line per WARNING or SEVERE record
(level, message and exception message; no stack trace). Warnings and errors
therefore always reach the terminal, including startup failures before the
database is open (missing `DB_URL`, `SAE_ID`, an invalid `SAE_NODES_FILE`).
INFO and below stay off the terminal.

Share state: a row is `KEYS_AVAILABLE` and carries the `lease_token` of the
operation that wrote it, the `issuing_sae_id` and the counterpart SAE. A share
is usable only when both SAEs hold a `KEYS_AVAILABLE` row with the same token
that name each other; the peer device is filled only after that check, made at
use time under both pair locks.

Pair locks (`node/pairlock`): every operation on a client pair (new share,
peer-device delivery, operator delete) locks the pair on both SAEs. The lock
of the SAE with the lower ID is taken first, then the higher one; a refusal
releases the first lock and ends the operation with "Another operation for this
device pair is in progress on an SAE. Retry later." Nobody waits for a lock. A
lock is an in-memory lease of 5 minutes keyed by the sorted pair of client
hashes, with a random 128-bit token and the issuing SAE. The holder renews
both leases every 60 s while the device transfer runs and synchronously
before and after each commit step; a failed renewal aborts the operation and
closes the device session. Every row write and delete runs in one
`BEGIN IMMEDIATE` transaction that checks the token, expiry and issuer of the
lease. Both locks are released by token, remote first.

New share: after the device ack the peer writes `KEYS_AVAILABLE(token)`
(`insert` over RMI; it resolves the key IDs at its own KME and writes the key
material and the row in one transaction), then the origin writes
`KEYS_AVAILABLE(token)`. If either write fails, the peer row is deleted by
token. "Share successful." follows the 100% line only after both writes and a
final renewal of both locks; otherwise the node logs a WARNING that the device
stored the keys but the share could not be recorded on both SAEs.

Operator delete: the node locks both SAEs, re-reads the shown row and deletes
the counterpart row (remote) first, then the shown row, both only if they
still carry the token the operator saw (compare-and-delete). A different token
leaves both rows and asks the operator again.

Open limitations: a device may hold keys after a failed commit without
"Share successful."; the operator provisions both devices again. The locks are
in memory, so an SAE restart releases all of its locks, and operations that
held one fail at their next renewal.

Device reads time out: 100 s while the node waits for the TLS handshake and the
device uplink, 15 minutes while the device wipes, takes the keys and acks. A
timeout ends the session with "Device did not respond in time. Session ended;
reconnect the device to start again." and the node waits for the next device.

On start the node runs a timed thread that deletes rows older than
`RECORD_RETENTION_DAYS` (default 14) immediately and then every 24 hours.
Key material follows via `ON DELETE CASCADE`. Independently of purge, any read
or serve path **refuses** rows older than retention (defense against restoring
an old DB file). Each expired row is deleted only while nobody holds its pair
lock (`PairLockRegistry.withFreePair`); a locked pair is purged on a later run.
[`provision_flow.drawio`](../../../diagrams/provision_flow.drawio) does not draw retention.

```bash
mkdir -p data
./migrate.sh env/node-1.env     # loads env and runs mvn flyway:migrate
./migrate-all.sh                # every env/node-*.env
```

Flyway scripts live in [`src/main/resources/db/migration`](src/main/resources/db/migration).
The schema is a single migration, `V1__Initial_create_script.sql`. With env already exported:

```bash
mvn -pl :sae-node flyway:migrate
```

## SAE directory

`SAE_NODES_FILE` names the SAE directory (`SaeNodes`): a JSON list with the public,
network-wide facts about every SAE, one entry per line:

```json
[
  { "saeId": "sae-1", "name": "Alice", "location": "Prague", "hostname": "127.0.0.1", "port": 2010, "spkiSha384": "<96 hex chars>" },
  { "saeId": "sae-2", "name": "Bob", "location": "Berlin", "hostname": "127.0.0.1", "port": 2020, "spkiSha384": "<96 hex chars>" }
]
```

| Field | Meaning |
| --- | --- |
| `saeId` | SAE id (`SAE_ID` of that node) |
| `name` | Node identity: leaf `certs/{name}.pem` and HSM key `{HSM_MLDSA_GROUP}/{name}`; letters, digits, `.`, `_`, `-` |
| `location` | Label in the operator's SAE menu and prompts |
| `hostname` | Advertised RMI address (`java.rmi.server.hostname`) and the address peers connect to |
| `port` | RMI registry port; the exported object listens on `port + 40000` |
| `spkiSha384` | RMI pin: lowercase hex SHA-384 of the leaf certificate's DER SubjectPublicKeyInfo (`KnownPeers`), 96 characters |

Every field is required. `saeId`, `name`, `spkiSha384` and `hostname` + `port` must each be
unique. Every site holds an identical copy, distributed out of band. The pins make the
file integrity-critical: whoever can change it chooses the node's peers. At startup the node:

- refuses a file that is not a regular file or that is group- or other-writable (checked on the
  symlink target, where the file system has POSIX permissions; use mode `0644` or stricter);
- takes its name, advertised hostname and RMI port from its own entry and fails if `SAE_ID` has none;
- requires its own entry's `spkiSha384` to match its own leaf, so a swapped certificate or
  directory stops the start.

In the lab, `env/sae-nodes.json` is that file. `scripts/rmi-pins.py` fills each entry's
`spkiSha384` from `certs/{name}.pem` (`PQC_CERTS_DIR` if set). It rewrites only the pins,
keeps the other fields and the layout, replaces the file atomically, writes only when a pin
changed, and keeps the mode at `0644` or stricter. `scripts/java.sh certgen`, `node` and
`lab-node` run it, so the pins follow every CertGenerator run (`./run-all.sh` included);
`scripts/java.sh pins` runs it alone. The `name` values must match `CERTGEN_NODES` in
`env/certgen.env`.

## RMI peers

- Registry on the own entry's `port`, exported object on `port + 40000`, both bound to `NODE_RMI_BIND`.
- Server side (`RmiPeerPinning`): after the mTLS handshake, a peer whose leaf is neither the local
  leaf nor pinned in the SAE directory is disconnected before any RMI byte is read. Client side: the
  server leaf must be pinned and, when the host and port belong to an SAE in the directory, map to that SAE.
- Caller identity (`RmiCallerContext`) is the SAE ID bound from the pinned TLS peer certificate,
  never a call argument. `NodeCommandsService` refuses calls without it. `lockPair` takes a
  lease in the caller's name; `renewPair` and `releasePair` act only on a lease the caller holds
  with the given token. `insert` requires the record's SAE ID to be the caller and a live lease
  of the caller with the given token. `deleteRecord` is a compare-and-delete under the caller's
  lease (`DELETED`, `ABSENT` or `TOKEN_MISMATCH`).
- Call arguments pass the JEP 290 allow-list `RmiSerialFilter` (only the `NodeCommands`
  argument types, with depth / reference / array / byte limits).
- Return values and the registry stub pass a process-wide JEP 290 reply filter that
  `RmiManager.start` installs: only the `NodeCommands` reply types, the stub classes and
  exceptions from `java.lang`, `java.io`, `java.rmi`, `java.sql` and `fel.cvut` are accepted.
- Distributed deletes are remote-first: the counterpart on the other SAE is deleted over RMI
  first, and the local row is deleted only if that call succeeds.

RMI commands (`NodeCommands`): `ping`, `getRecordMetadata`, `lockPair`, `renewPair`,
`releasePair`, `insert`, `deleteRecord`. The lock calls take the pair of client hashes and the
token.

Startup checks and one pinned call are drawn in
[`diagrams/rmi_pinning.drawio`](../../../diagrams/rmi_pinning.drawio).

## Source layout

```text
modules/sae-node/
  README.md
  pom.xml
  src/main/java/fel/cvut/node/      Node, bootstrap, PeerRecordSync, ProvisionSession
    interNodeCommunication/         RMI: RmiManager, NodeCommandsService, SaeNodes, KnownPeers,
                                    RmiPeerPinning, RmiCallerContext, RmiSerialFilter
    pairlock/                       Pair locks: PairLocks, PairOperation, PairLockRegistry
    recordManager/                  Client records
  src/main/java/fel/cvut/db/        JDBC + repositories + RecordRetention
  src/main/java/fel/cvut/qkd/       ETSI 014 client, Qkd014Demo
  src/main/resources/db/migration/  Flyway SQL
  src/test/java/fel/cvut/harness/   Shared SAE test harness (fixtures, in-process RMI, mock KME)
  src/test/java/fel/cvut/           DB, node, RMI, QKD, peer-sync tests,
                                    unit/utimaco/HsmFailClosedTest
```

`fel.cvut.se` and `fel.cvut.terminal` live in [se-wire](../se-wire/src/main/java/fel/cvut/), `tls/Software*` and `TlsStores` in [tls-software](../tls-software/src/main/java/fel/cvut/tls/), and `HsmNodeTls`, `TlsProviders` and `fel.cvut.utimaco` in [tls-hsm](../tls-hsm/src/main/java/fel/cvut/).

USB CDC helpers live in [usb-cdc](../usb-cdc/README.md). TLS/HSM helpers here
are also used by CertGenerator.

## TLS profiles

| Use | Profile | Trust |
| --- | --- | --- |
| Inter-node RMI | `PURE_PQC` (TLS 1.3 + MLKEM768 + mldsa44) | `certs/ca/root-ca.pem` only, plus the `spkiSha384` pins of the SAE directory |
| Device `PROVISION` on USB CDC | `PURE_PQC` | `certs/ca/client_ca.pem` only (device certs) |
| QKD KME mTLS | `CLASSICAL` (prefer TLS 1.3 + MLKEM768 + mldsa44; allow TLS 1.2 + x25519 / classical signatures) | `QKD_TRUSTSTORE_PATH` |

Provider routing is documented in the [JAVA_APPS README](../../README.md#tls).
