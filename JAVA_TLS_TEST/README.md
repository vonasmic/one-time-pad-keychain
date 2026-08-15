# JAVA_TLS_TEST

Java SAE node stack using **Bouncy Castle JSSE** for the TLS protocol engine, **Utimaco SecurityServer JCE** for classical crypto, and **PQMI** for HSM ML-DSA identity signing.

## TLS

- Profiles: `NodeTls.TlsProfile.CLASSICAL` (TLS 1.3 + x25519) and `PURE_PQC` (TLS 1.3 + MLKEM768 + mldsa44)
- Inter-node RMI and the inbound command server use `PURE_PQC`
- QKD KME mTLS uses `CLASSICAL` with CryptoServer HSM keys (`CertGenerator` option 2 → `QKD_HSM_KEY_ALIAS`); truststore is public KME CA only
- Node identity: `CertGenerator` option 3 (default) → all `certs/{Node}.pem` → HSM keys + refreshed leaf certs + native client bundle

### Provider routing (`TlsProviders.install`)


| Need                                | Provider                             | How                                                            |
| ----------------------------------- | ------------------------------------ | -------------------------------------------------------------- |
| Classical algs (AES, EC, x25519, …) | Utimaco `CryptoServer` JCE           | `Security.insertProviderAt`                                    |
| ML-KEM768 + ML-DSA verify           | Bouncy Castle (`bcprov`)             | next in global provider order                                  |
| ML-DSA HSM sign                     | PQMI shim                            | BC JSSE **alternate** only (not in `Security`)                 |
| TLS protocol                        | `BouncyCastleJsseProvider` (`bctls`) | wired with `JcaTlsCryptoProvider` (default helper + alternate) |


## HSM / PQMI


| File                                                                              | Role                                                                    |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `[tls/NodeTls.java](src/main/java/fel/cvut/tls/NodeTls.java)`                     | Public TLS API: profiles, `SSLContext` factories, server sockets        |
| `[tls/TlsProviders.java](src/main/java/fel/cvut/tls/TlsProviders.java)`           | JCE/JSSE bootstrap, CryptoServer keystore import/load, PQMI ML-DSA shim |
| `[tls/TlsStores.java](src/main/java/fel/cvut/tls/TlsStores.java)`                 | Trust/leaf PEM & PKCS#12 loading (public material)                      |
| `[utimaco/Pqmi.java](src/main/java/fel/cvut/utimaco/Pqmi.java)`                   | HSM env + ephemeral CXI/PQMI ops (ML-DSA keygen/sign)                   |
| `[utimaco/HsmGate.java](src/main/java/fel/cvut/utimaco/HsmGate.java)`             | Serializes PQMI CXI and CryptoServer JCE access to one device           |
| `[certGen/CertGenerator.java](src/main/java/fel/cvut/certGen/CertGenerator.java)` | Provision: PQC node certs + QuKayDee PKCS#12 → HSM                      |


`Node` owns a `Pqmi` config handle and `SSLContext`; `TlsProviders.install` keeps one logged-in CryptoServer JCE provider for the JVM. Both paths use `HsmGate` so CXI and JCE never overlap on the HSM.

Node identity is `certs/{Node}.pem` plus the HSM key (`{HSM_MLDSA_GROUP}/{Node}`). Legacy `certs/{Node}.p12` files from the old software-keystore path are not used at runtime.

`vendor/pqmi-java/` is copied locally from Utimaco QuantumProtect Java_UTI (not committed; Utimaco license). Maven compiles it as an extra source root.

`vendor/securityserver-jce.jar` is the Utimaco SecurityServer JCE provider (`CryptoServerProvider`). Referenced from `pom.xml` as a system-scoped dependency — place the jar under `vendor/` (not committed; Utimaco license).

`vendor/cryptoservercxi.jar` is the full CryptoServer CXI API (from Utimaco `CryptoServerCXI.jar`), pre-adjusted for JCE compatibility (`CryptoServerCXI.Item` and `TAG_*` are public). Copy from your Utimaco install only if you upgrade SDK versions — then re-apply the same visibility patch or keep this vendor copy.

### HSM one-time init (csadm)

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

HSM connection lives in `env/hsm.env` (shared). Each node env sets `TLS_NODE_ID` to pick its HSM key and leaf cert (`certs/{TLS_NODE_ID}.pem`). After HSM reinit, run CertGenerator (default option 3) before starting nodes — runtime does not create HSM keys automatically.

```bash
./run-node.sh env/node-1.env   # sources env/hsm.env, then node env
```

## Database

PostgreSQL stores client record state. Use **one database per node** (e.g. `qkd-db-sae-1` for `sae-1`).

### Setup

1. Copy `.env.example` → `.env` (or use `env/node-N.env` for multi-node).
2. Set `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` in that file.
3. Create the database:

```bash
createdb qkd-db-sae-1
```

1. Run migrations **before starting a node**:

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

