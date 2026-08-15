# JAVA_TLS_TEST

Java SAE node stack using **Bouncy Castle JSSE** for the TLS protocol engine, **Utimaco SecurityServer JCE** for classical crypto, and **PQMI** for HSM ML-DSA identity signing.

## Contents

- [TLS](#tls)
- [HSM / PQMI](#hsm--pqmi)
- [Terminal app](#terminal-app)
- [HSM setup](#hsm-setup)
- [Database](#database)

## TLS

- Profiles: `NodeTls.TlsProfile.CLASSICAL` (TLS 1.3 + x25519) and `PURE_PQC` (TLS 1.3 + MLKEM768 + mldsa44)
- Inter-node RMI, the inbound command server, and the terminal gateway all use `PURE_PQC`
- QKD KME mTLS uses `CLASSICAL` with CryptoServer HSM keys (`CertGenerator` option 2 → `QKD_HSM_KEY_ALIAS`); truststore is public KME CA only
- Node identity: `CertGenerator` option 3 (default) → all `certs/{Node}.pem` → HSM keys + refreshed leaf certs + native client bundle

### Provider routing (`TlsProviders.install`)

`NodeTls.install(session)` (also used by the TLS context factories) logs into CryptoServer,
then `installOrdered(...)` so `Security` order is this list, highest priority first:

| # | Provider                            | Need                                         | How                                                                 |
| - | ----------------------------------- | -------------------------------------------- | ------------------------------------------------------------------- |
| 1 | `BouncyCastleJsseProvider` (`bctls`) | TLS protocol                                  | helper pinned to BC; alternate = `HsmSigningProvider`               |
| 2 | Utimaco `CryptoServer` JCE          | Unscoped JCE (AES, KeyGen, …) HSM-first      | one logged-in instance for the JVM lifetime                         |
| 3 | Bouncy Castle (`bcprov`)            | ML-KEM, verify, PEM/PKCS#12                   | `installOrdered` reseats any pre-existing `BC`                      |
| — | `HsmSigningProvider`                | TLS identity sign (CryptoServer or PQMI)      | JSSE **alternate** only (not in `Security`); `HsmGate` + audit log  |

JSSE tries BC `initSign` first; an HSM private key fails with `InvalidKeyException`, then the
alternate signs on the HSM. There is no software fallback for TLS identity keys.
`NodeTls.TlsProfile` is a data-driven enum (protocols/named-groups/signature-schemes per
constant), so adding or tuning a cipher profile means editing one enum constant, not a
switch statement.

## HSM / PQMI

| File                                                                              | Role                                                                    |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [`tls/NodeTls.java`](src/main/java/fel/cvut/tls/NodeTls.java)                     | Public TLS API: profiles, `SSLContext` factories, server sockets        |
| [`tls/TlsProviders.java`](src/main/java/fel/cvut/tls/TlsProviders.java)           | JCE/JSSE bootstrap, CryptoServer keystore import/load, PQMI ML-DSA shim |
| [`tls/TlsStores.java`](src/main/java/fel/cvut/tls/TlsStores.java)                 | Trust/leaf PEM & PKCS#12 loading (public material)                      |
| [`utimaco/Pqmi.java`](src/main/java/fel/cvut/utimaco/Pqmi.java)                   | HSM env + ephemeral CXI/PQMI ops (ML-DSA keygen/sign)                   |
| [`utimaco/HsmGate.java`](src/main/java/fel/cvut/utimaco/HsmGate.java)             | Serializes PQMI CXI and CryptoServer JCE access to one device           |
| [`certGen/CertGenerator.java`](src/main/java/fel/cvut/certGen/CertGenerator.java) | Provision: PQC node certs + QuKayDee PKCS#12 → HSM                      |

`Node` owns a `Pqmi` config handle and `SSLContext`; `TlsProviders.install` keeps one logged-in CryptoServer JCE provider for the JVM. Both paths use `HsmGate` so CXI and JCE never overlap on the HSM.

## Terminal app

The operator console (target SAE/client selection, shared-record deletion confirmation) runs as
its own process, `fel.cvut.terminalapp.TerminalApp`, instead of blocking inside the node on stdin.

- The terminal app connects to a node's dedicated terminal gateway port using the **same TLS
  bootstrap nodes use to talk to each other**: `NodeTls.createContextForNode` (HSM-backed identity)
  + `NodeTls.TlsProfile.PURE_PQC`. It authenticates like any other node — provision its identity
  the same way (`CertGenerator`, `certs/{TLS_NODE_ID}.pem`).
- `Node` runs `TerminalGateway` (`fel.cvut.node.TerminalGateway`), a small TLS server on
  `NODE_TERMINAL_PORT` that accepts exactly one terminal session at a time and implements
  `fel.cvut.terminal.OperatorConsole` by forwarding requests to it over a newline-delimited JSON
  protocol (`fel.cvut.terminal.TerminalWireProtocol`).
- `InputHandler`/`Node` depend only on the `OperatorConsole` abstraction — `TerminalGateway` (remote,
  used by `Node`) and `LocalOperatorConsole` (stdin, used by `TerminalApp` itself) are its two
  implementations.

Run it with:

```bash
export TLS_NODE_ID=Terminal      # HSM identity provisioned via CertGenerator
export NODE_HOSTNAME=127.0.0.1   # node to connect to
export NODE_TERMINAL_PORT=...    # node's terminal gateway port
export NODE_NATIVE_PORT=11111    # node's TLS command server (USB CDC is redirected here)
mvn exec:java -Dexec.mainClass=fel.cvut.terminalapp.TerminalApp
```

### USB redirect (embedded device)

The terminal app is the **sole native-client endpoint** for the embedded (STM32) device — the
node itself has no USB awareness. USB is **required**: `TerminalApp` opens `/dev/ttyACM0` (override
with `USB_SERIAL_PORT`), asserts DTR/RTS, waits for the device's TLS ClientHello (`0x16`), then
forwards bytes to `NODE_NATIVE_PORT`. Startup fails if the port cannot be opened.

```bash
export NODE_NATIVE_PORT=11111
# export USB_SERIAL_PORT=/dev/ttyACM0   # default
export USB_BAUD_RATE=115200             # optional
```

| File                                                                                  | Role                                                                  |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [`terminal/OperatorConsole.java`](src/main/java/fel/cvut/terminal/OperatorConsole.java) | Abstraction over operator interactions a node needs                  |
| [`terminal/LocalOperatorConsole.java`](src/main/java/fel/cvut/terminal/LocalOperatorConsole.java) | stdin-backed `OperatorConsole`, used by `TerminalApp`         |
| [`terminal/TerminalWireProtocol.java`](src/main/java/fel/cvut/terminal/TerminalWireProtocol.java) | Newline-delimited JSON request/response protocol              |
| [`node/TerminalGateway.java`](src/main/java/fel/cvut/node/TerminalGateway.java)         | Node-side TLS endpoint + remote `OperatorConsole` implementation      |
| [`terminalapp/TerminalApp.java`](src/main/java/fel/cvut/terminalapp/TerminalApp.java)   | Standalone terminal app entry point                                   |
| [`terminalapp/UsbTcpBridge.java`](src/main/java/fel/cvut/terminalapp/UsbTcpBridge.java) | USB-serial ↔ node TCP command-server byte relay for the embedded device |

Node identity is `certs/{Node}.pem` plus the HSM key (`{HSM_MLDSA_GROUP}/{Node}`). Legacy `certs/{Node}.p12` files from the old software-keystore path are not used at runtime.

`vendor/pqmi-java/` is copied locally from Utimaco QuantumProtect Java_UTI (not committed; Utimaco license). Maven compiles it as an extra source root.

`vendor/securityserver-jce.jar` is the Utimaco SecurityServer JCE provider (`CryptoServerProvider`). Referenced from `pom.xml` as a system-scoped dependency — place the jar under `vendor/` (not committed; Utimaco license).

`vendor/cryptoservercxi.jar` is the full CryptoServer CXI API (from Utimaco `CryptoServerCXI.jar`), pre-adjusted for JCE compatibility (`CryptoServerCXI.Item` and `TAG_*` are public). Copy from your Utimaco install only if you upgrade SDK versions — then re-apply the same visibility patch or keep this vendor copy.

## HSM setup

### One-time init (csadm)

Unzip both Utimaco SDKs into one parent folder and run everything from there:

```
<hsm-workspace>/
  u.trust-GP-HSM-Simulator_v6.5.0.0/     # ADMIN key (SecurityServer simulator package)
  QuantumProtect-1.5.0.0-Evaluation/     # QP simulator + PQC firmware (.mtc)
```

Requires `csadm` on `PATH` (Utimaco SecurityServer install). PIN `12345678` must match `env/hsm.env`.

**Linux (bash)** — Terminal 1 can be run from `<hsm-workspace>` (`cs_sim.sh` finds its own directory). Terminal 2: `cd` to `<hsm-workspace>`.

Terminal 1 — start simulator (leave running):

```bash
cd <hsm-workspace>
./QuantumProtect-1.5.0.0-Evaluation/linux/sim5_linux/bin/cs_sim.sh
```

Terminal 2 — one-time init (Quantum Protect Quick Start 4.4–4.6):

```bash
cd <hsm-workspace>
export ADMIN_KEY=u.trust-GP-HSM-Simulator_v6.5.0.0/Software/Linux/Administration/key/ADMIN_SIM.key
export QP_FW=QuantumProtect-1.5.0.0-Evaluation/linux/firmware/1.5.0.0/sim5_linux
export DEV=3001@127.0.0.1

csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY GetState
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY ListUsers
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY DeleteUser=CXI_HMAC
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY AddUser=CXI_HMAC,00000002{CXI_GROUP=*},hmacpwd,87654321
csadm Dev=$DEV LogonPass=CXI_HMAC,87654321 ChangeUser=CXI_HMAC,12345678
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY ListUsers
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY MBKListKeys
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY LoadFile=$QP_FW/hbs_sim_linux.mtc LoadFile=$QP_FW/ml_sim_linux.mtc LoadFile=$QP_FW/pqmi_sim_linux.mtc Restart
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY GetBootLog
csadm Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY ListFirmware
```

**Windows (PowerShell)** — Terminal 1 must `cd` into `bin` first (`cs_sim.bat` runs `.\bl_sim5.exe` relative to the current directory, not the batch file). Terminal 2: `cd` to `<hsm-workspace>`.

Terminal 1 — start simulator (leave running):

```powershell
cd <hsm-workspace>\QuantumProtect-1.5.0.0-Evaluation\windows\sim5_windows\bin
.\cs_sim.bat
```

Terminal 2 — one-time init (Quantum Protect Quick Start 4.4–4.6):

```powershell
cd <hsm-workspace>
$env:ADMIN_KEY = "u.trust-GP-HSM-Simulator_v6.5.0.0\Software\Windows\Administration\key\ADMIN_SIM.key"
$env:QP_FW     = "QuantumProtect-1.5.0.0-Evaluation\windows\firmware\1.5.0.0\sim5_windows"
$env:DEV        = "3001@127.0.0.1"

csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY GetState
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY ListUsers
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY DeleteUser=CXI_HMAC
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY AddUser="CXI_HMAC,00000002{CXI_GROUP=*},hmacpwd,87654321"
csadm Dev=$env:DEV LogonPass=CXI_HMAC,87654321 ChangeUser=CXI_HMAC,12345678
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY ListUsers
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY MBKListKeys
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY LoadFile=$env:QP_FW\hbs_sim_win.mtc LoadFile=$env:QP_FW\ml_sim_win.mtc LoadFile=$env:QP_FW\pqmi_sim_win.mtc Restart
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY GetBootLog
csadm Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY ListFirmware
```

`unable to open Keyfile` means `ADMIN_KEY` does not point at a real file — run from `<hsm-workspace>` and verify with `Test-Path $env:ADMIN_KEY` (Windows) or `test -f "$ADMIN_KEY"` (Linux).

Skip the `LoadFile` line if the QP simulator already has PQ modules. Physical cHSM: `ADMIN_CAAK.key`, `DEV=4001@<host>`, firmware under `.../uta/`.

### Provision (CertGenerator)

With the simulator running:

```bash
cp env/example/hsm.env.example env/hsm.env
set -a && source env/hsm.env && set +a
mvn exec:java -Dexec.mainClass=fel.cvut.certGen.CertGenerator
```

1. **Full provision (default, option 3)** — discovers node names from `certs/*.pem` (except `root-ca.pem`), creates missing PQMI ML-DSA keys in HSM, refreshes leaf PEMs, writes `certs/client/` for `tls_native/tls_client`
2. **Import QuKayDee SAE PKCS#12** — RSA key into CryptoServer (`QKD_HSM_KEY_ALIAS`); prompts for PKCS#12 password (default `password`); PKCS#12 can be deleted after
3. **Single PQC node cert (option 1)** — one node at a time with optional HSM key overwrite

Root CA stays in `root-ca.p12` (software).

### Node startup

`env/hsm.env` (copy from `env/example/hsm.env.example`) holds the Utimaco connection
(`HSM_DEVICE`, `HSM_USER`, `HSM_PIN`, `HSM_MLDSA_GROUP`) shared by every node process. Each
node's own env file (`env/node-N.env`, from `env/example/.env.example`) sets `TLS_NODE_ID` to
select its HSM key and leaf cert (`certs/{TLS_NODE_ID}.pem`). Source both before starting a node
— there is no wrapper script:

```bash
set -a
source env/hsm.env
source env/node-1.env
set +a
mvn exec:java -Dexec.mainClass=fel.cvut.node.Node
```

After an HSM reinit, run `CertGenerator` (option 3) before starting nodes — the node process does
not create HSM keys automatically.

## Database

PostgreSQL stores client record state. Use **one database per node** (e.g. `qkd-db-sae-1` for `sae-1`).

### Setup

1. Copy `.env.example` → `.env` (or use `env/node-N.env` for multi-node).
2. Set `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` in that file.
3. Create the database:

   ```bash
   createdb qkd-db-sae-1
   ```

4. Run migrations **before starting a node**:

   ```bash
   ./migrate.sh              # uses .env
   ./migrate.sh env/node-1.env
   ./migrate-all.sh          # all env/node-*.env (node-1, node-2, node-3, …)
   ```

   The script loads env vars and runs `mvn flyway:migrate`.

Alternatively, with env already exported:

```bash
export DB_URL=jdbc:postgresql://localhost:5432/qkd-db-sae-1
export DB_USERNAME=postgres
export DB_PASSWORD=postgres
mvn flyway:migrate
```

