# JAVA_TLS_TEST

Java applications using **Bouncy Castle JSSE** for the TLS protocol engine, **Utimaco SecurityServer JCE** for classical crypto (SAE / CertGenerator / TerminalBridge), and **PQMI** for HSM ML-DSA identity signing. **UserApp does not use the HSM.**

The device connects to **two** of these processes over USB CDC: **USER** (UserApp) and **SAE** (SaeNode, usually via TerminalBridge). UserApp is not an SAE.

Applications live under `src/`. Maven modules: `se-wire`, `usb-cdc`, `tls-software`, `tls-hsm`, `cert-generator`, `user-app`, `sae-node`, `terminal-bridge`, `lab-switch`. Run every `mvn -pl :<module> -am exec:java` from `JAVA_TLS_TEST` so `certs/` and `env/` resolve. UserApp depends on `tls-software` only (no HSM / RMI / DB).

| Application | Entry point | README |
| --- | --- | --- |
| [CertGenerator](src/CertGenerator/README.md) | `fel.cvut.certGen.CertGenerator` | PKI / HSM provision |
| [SaeNode](src/SaeNode/README.md) | `fel.cvut.node.Node` | **SAE**: QKD, DB, RMI, provision TLS server |
| [TerminalBridge](src/TerminalBridge/README.md) | `fel.cvut.terminalapp.TerminalApp` | SAE operator console + optional USB relay for `PROVISION` |
| [UserApp](src/UserApp/README.md) | `fel.cvut.userapp.UserApplication` | **USER**: USB OTP encrypt / decrypt / manage (not SAE) |
| [LabSwitch](src/LabSwitch/README.md) | `fel.cvut.lab.LabSwitchApp` | Lab cable + client selector (`./run-all.sh` only) |

## Contents

- [TLS](#tls)
- [HSM / PQMI](#hsm--pqmi)
- [HSM setup](#hsm-setup)

## TLS

- Profiles: `SoftwareTls.TlsProfile.PURE_PQC` (TLS 1.3 + MLKEM768 + mldsa44 only) and `CLASSICAL` (same PQC preferred, then TLS 1.2 + x25519 / classical signatures)
- Inter-node RMI and the terminal gateway use `PURE_PQC` with SAE `root-ca` trust
- The SAE inbound command server (`NODE_NATIVE_PORT`) uses `PURE_PQC` with the same HSM node identity; client auth trusts `client_ca` (**device** certs for `PROVISION`). UserApp is a separate TLS server over CDC and is not this socket.
- QKD KME mTLS uses `CLASSICAL` with CryptoServer HSM keys (`CertGenerator` imports `certs/qkd/*-client.p12` → `QKD_HSM_KEY_ALIAS`); truststore is public KME CA only
- Node identity: `CertGenerator` (`env/certgen.env`) → listed node PEMs + HSM keys, client CA, device/user bundles, and QuKayDee PKCS#12 import

### Provider routing (`TlsProviders.install`)

`HsmNodeTls.install(session)` (also used by the TLS context factories) logs into CryptoServer,
then `installOrdered(...)` so `Security` order is this list, highest priority first:

| # | Provider                            | Need                                         | How                                                                 |
| - | ----------------------------------- | -------------------------------------------- | ------------------------------------------------------------------- |
| 1 | `BouncyCastleJsseProvider` (`bctls`) | TLS protocol                                  | helper pinned to BC; alternate = `HsmSigningProvider`               |
| 2 | Utimaco `CryptoServer` JCE          | Unscoped JCE (AES, KeyGen, …) HSM-first      | one logged-in instance for the JVM lifetime                         |
| 3 | Bouncy Castle (`bcprov`)            | ML-KEM, verify, PEM/PKCS#12                   | `installOrdered` reseats any pre-existing `BC`                      |
| — | `HsmSigningProvider`                | TLS identity sign (CryptoServer or PQMI)      | JSSE **alternate** only (not in `Security`); `HsmGate` + audit log  |

JSSE tries BC `initSign` first; an HSM private key fails with `InvalidKeyException`, then the
alternate signs on the HSM. There is no software fallback for TLS identity keys.
`SoftwareTls.TlsProfile` is a data-driven enum (protocols/named-groups/signature-schemes per
constant), so adding or tuning a cipher profile means editing one enum constant, not a
switch statement.

## HSM / PQMI

| File | Role |
| --- | --- |
| [`tls/SoftwareTls.java`](src/SaeNode/main/java/fel/cvut/tls/SoftwareTls.java) | Software TLS: profiles, PEM/PKCS#12, USB wrapServer |
| [`tls/HsmNodeTls.java`](src/SaeNode/main/java/fel/cvut/tls/HsmNodeTls.java) | SAE HSM TLS factories |
| [`tls/TlsProviders.java`](src/SaeNode/main/java/fel/cvut/tls/TlsProviders.java) | JCE/JSSE bootstrap, CryptoServer keystore import/load, PQMI ML-DSA shim |
| [`tls/TlsStores.java`](src/SaeNode/main/java/fel/cvut/tls/TlsStores.java) | Trust/leaf PEM & PKCS#12 loading (public material) |
| [`utimaco/Pqmi.java`](src/SaeNode/main/java/fel/cvut/utimaco/Pqmi.java) | HSM env + ephemeral CXI/PQMI ops (ML-DSA keygen/sign) |
| [`utimaco/HsmGate.java`](src/SaeNode/main/java/fel/cvut/utimaco/HsmGate.java) | Serializes PQMI CXI and CryptoServer JCE access to one device |
| [`certGen/CertGenerator.java`](src/CertGenerator/main/java/fel/cvut/certGen/CertGenerator.java) | Provision: PQC node certs + QuKayDee PKCS#12 → HSM |

`Node` owns a `Pqmi` config handle and `SSLContext`; `TlsProviders.install` keeps one logged-in CryptoServer JCE provider for the JVM. Both paths use `HsmGate` so CXI and JCE never overlap on the HSM.

How to run the operator console and the optional USB↔TCP pump:
[`src/TerminalBridge/README.md`](src/TerminalBridge/README.md).

How to run the USB OTP encrypt/decrypt console (no HSM):
[`src/UserApp/README.md`](src/UserApp/README.md).

Node identity is `certs/{Node}.pem` plus the HSM key (`{HSM_MLDSA_GROUP}/{Node}`).

`vendor/pqmi-java/` is copied locally from Utimaco QuantumProtect Java_UTI (not committed; Utimaco license). Maven compiles it as an extra source root.

`vendor/securityserver-jce.jar` is the Utimaco SecurityServer JCE provider (`CryptoServerProvider`). Referenced from `pom.xml` as a system-scoped dependency — place the jar under `vendor/` (not committed; Utimaco license).

`vendor/cryptoservercxi.jar` is the full CryptoServer CXI API (from Utimaco `CryptoServerCXI.jar`), pre-adjusted for JCE compatibility (`CryptoServerCXI.Item` and `TAG_*` are public). Copy from your Utimaco install only if you upgrade SDK versions — then re-apply the same visibility patch or keep this vendor copy.

## HSM setup

Unzip the Utimaco SDKs into the repo (contents are gitignored; see the folder READMEs):

- [`ultimaco/hsm-simulator/`](../ultimaco/hsm-simulator/README.md) — SecurityServer / ADMIN key / `csadm`
- [`ultimaco/quantum-protect/`](../ultimaco/quantum-protect/README.md) — QP simulator + PQC firmware (`.mtc`)

PIN `12345678` must match `env/hsm.env`. From the **repo root**, `./run-all.sh` (or `scripts/hsm.sh`) talks to an already-running simulator and runs one-time `csadm` init when `CXI_HMAC` / PQMI firmware are missing. It does not start the Windows simulator.

Paths below use the git root so they work from any directory.

**Linux (bash)** — `cs_sim.sh` finds its own directory. `csadm` is the binary in `hsm-simulator`, not something on `PATH`.

Terminal 1 — start simulator (leave running):

```bash
ROOT="$(git rev-parse --show-toplevel)"
"$ROOT/ultimaco/quantum-protect/linux/sim5_linux/bin/cs_sim.sh"
```

Terminal 2 — one-time init (Quantum Protect Quick Start 4.4–4.6):

```bash
ROOT="$(git rev-parse --show-toplevel)"
export ADMIN_KEY="$ROOT/ultimaco/hsm-simulator/Software/Linux/Administration/key/ADMIN_SIM.key"
export QP_FW="$ROOT/ultimaco/quantum-protect/linux/firmware/1.5.0.0/sim5_linux"
export CSADM="$ROOT/ultimaco/hsm-simulator/Software/Linux/Administration/csadm"
export DEV=3001@127.0.0.1

"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY GetState
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY ListUsers
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY DeleteUser=CXI_HMAC
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY AddUser=CXI_HMAC,00000002{CXI_GROUP=*},hmacpwd,87654321
"$CSADM" Dev=$DEV LogonPass=CXI_HMAC,87654321 ChangeUser=CXI_HMAC,12345678
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY ListUsers
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY MBKListKeys
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY LoadFile=$QP_FW/hbs_sim_linux.mtc LoadFile=$QP_FW/ml_sim_linux.mtc LoadFile=$QP_FW/pqmi_sim_linux.mtc Restart
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY GetBootLog
"$CSADM" Dev=$DEV LogonSign=ADMIN,$ADMIN_KEY ListFirmware
```

**Windows (PowerShell)** — Terminal 1 must `cd` into `bin` first (`cs_sim.bat` runs `.\bl_sim5.exe` relative to the current directory, not the batch file).

Terminal 1 — start simulator (leave running):

```powershell
$ROOT = (git rev-parse --show-toplevel)
cd $ROOT\ultimaco\quantum-protect\windows\sim5_windows\bin
.\cs_sim.bat
```

Terminal 2 — one-time init (Quantum Protect Quick Start 4.4–4.6):

```powershell
$ROOT = (git rev-parse --show-toplevel)
$env:ADMIN_KEY = "$ROOT\ultimaco\hsm-simulator\Software\Windows\Administration\key\ADMIN_SIM.key"
$env:QP_FW     = "$ROOT\ultimaco\quantum-protect\windows\firmware\1.5.0.0\sim5_windows"
$env:CSADM     = "$ROOT\ultimaco\hsm-simulator\Software\Windows\Administration\csadm.exe"
$env:DEV        = "3001@127.0.0.1"

& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY GetState
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY ListUsers
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY DeleteUser=CXI_HMAC
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY AddUser="CXI_HMAC,00000002{CXI_GROUP=*},hmacpwd,87654321"
& $env:CSADM Dev=$env:DEV LogonPass=CXI_HMAC,87654321 ChangeUser=CXI_HMAC,12345678
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY ListUsers
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY MBKListKeys
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY LoadFile=$env:QP_FW\hbs_sim_win.mtc LoadFile=$env:QP_FW\ml_sim_win.mtc LoadFile=$env:QP_FW\pqmi_sim_win.mtc Restart
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY GetBootLog
& $env:CSADM Dev=$env:DEV LogonSign=ADMIN,$env:ADMIN_KEY ListFirmware
```

`unable to open Keyfile` means `ADMIN_KEY` does not point at a real file — verify with `Test-Path $env:ADMIN_KEY` (Windows) or `test -f "$ADMIN_KEY"` (Linux).

Skip the `LoadFile` line if the QP simulator already has PQ modules. Physical cHSM: `ADMIN_CAAK.key`, `DEV=4001@<host>`, firmware under `.../uta/`.

### Provision (CertGenerator)

Full description, run commands, and every env variable:
[`src/CertGenerator/README.md`](src/CertGenerator/README.md).

With the simulator running:

```bash
cp env/example/hsm.env.example env/hsm.env
cp env/example/certgen.env.example env/certgen.env
set -a && source env/hsm.env && set +a
mvn -pl :cert-generator -am exec:java
```

From the repo root the same run is `scripts/java.sh certgen`.

No menu. Missing CAs, node HSM keys / PEMs, client bundles, and QuKayDee PKCS#12 aliases
are created or imported; existing material is left alone.

SAE root CA stays in `certs/ca/root-ca.p12` (software). Client CA stays in `certs/ca/client_ca.p12` (software) for the Java user bundle and for signing on-chip device CSRs. The device does **not** embed a client CA: ENCRYPT/DECRYPT pin the TLS peer to the enrolled owner key (UserApp cert). Enroll over USB `OWNER SET` (unsigned blob: reset password + owner SPKI + optional SAE CA). Device ML-DSA is generated on-chip; `CLIENT CSR` + MANAGE `CREDS DEVICE` (cert only) install the leaf.

### Node startup

`env/hsm.env` (copy from `env/example/hsm.env.example`) holds the Utimaco connection
(`HSM_DEVICE`, `HSM_USER`, `HSM_PIN`, `HSM_MLDSA_GROUP`) shared by every node process. Each
node's own env file (`env/node-N.env`, from `env/example/.env.example`) sets `TLS_NODE_ID` to
select its HSM key and leaf cert (`certs/{TLS_NODE_ID}.pem`). From the repo root:

```bash
scripts/java.sh node env/node-1.env
```

Or source both env files and run Maven from `JAVA_TLS_TEST` — Java only sees process environment
variables:

```bash
set -a
source env/hsm.env
source env/node-1.env
set +a
mvn -pl :sae-node -am exec:java
```

After an HSM reinit, run `CertGenerator` before starting nodes — the node process does
not create HSM keys automatically.

Database setup and every node env variable: [`src/SaeNode/README.md`](src/SaeNode/README.md).

