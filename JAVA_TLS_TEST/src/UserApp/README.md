# UserApp

**USER** application: USB console for the home-PC user. This is **not** an SAE.
The device connects to this process for OTP **encrypt / decrypt** and **MANAGE**
(INIT / OWNER / PEER / CREDS). Provision is a separate **SAE** path: the SAE
node plus [TerminalBridge](../TerminalBridge/README.md). This process does
**not** use the HSM: the owner ML-DSA key is loaded from `certs/user/user.p12` (or
PEM fallback) into Bouncy Castle JSSE. The user key is never embedded in firmware.

Entry point: `fel.cvut.userapp.UserApplication`.

Working directory must be `JAVA_TLS_TEST` (so `certs/` resolves).

## Prompt

`quit` / `q` / `exit` leaves. Recognized **APP** commands run Java wrappers; any other
line is sent straight to the chip console (same as TerminalBridge transact).

### APP commands

| Command | What it does |
| --- | --- |
| `ENCRYPT` / `E` | Arm TLS encrypt, send PIN + message, print pad reply hex |
| `DECRYPT` / `D` | Arm TLS decrypt, send PIN + encrypt reply (empty = last) |
| `LEFT` / `OTP LEFT` | USB `TROPIC OTP LEFT` dump — remaining/capacity pad bytes, no PIN |
| `PEER ADD` | nickname + 96-hex peer hash + PIN → unsigned MANAGE TLS |
| `PEER LIST` / `PEER REMOVE` | LIST is USB; REMOVE is unsigned MANAGE TLS with PIN |
| `INIT LAB` | Lab enrollment: OWNER SET, MANAGE KEYGEN (empty ECC only), KEM INIT, CLIENT CSR, local client-CA sign, CREDS DEVICE. Never pairs |
| `INIT PROD` | Production enrollment: same identity path **without** local CA sign; optional MANAGE PAIRING. Warns before running |
| `OWNER` | Enroll this UserApp cert (`OWNER SET` unsigned blob + reset password + SAE CA) |
| `REPLACE` | `OWNER REPLACE` over unsigned MANAGE TLS (reset password, not M&D) |

USB command for OTP is `{MODE} {unix}`. After TLS this process is a loopback
TLS server over CDC. PIN for ENCRYPT/DECRYPT is **only inside TLS**.

`PEER ADD` takes a 96-hex SHA-384 of the peer SPKI (same width firmware stores). The UserApp certificate **is** the device owner key.

### Chip lines (passthrough)

Any line that is not an APP command is written to the chip. ASCII success
(`HELP`, `TROPIC PING`) or a `0xB1` dump is printed. Errors are `failed`.

- `CLIENT HASH` / `CLIENT CSR` / `TROPIC PUB` / `TROPIC OTP LEFT` / `PEER LIST` are dump frames.
- `PROVISION`, `ENCRYPT`, `DECRYPT`, and `MANAGE` are **refused** on passthrough: they switch the pipe
  to opaque TLS. Use APP ENCRYPT/DECRYPT/PEER/INIT LAB/INIT PROD, or TerminalBridge for provision.

### INIT LAB / INIT PROD

The prompt shows **Profile: LAB** or **Profile: PROD**. Bare `INIT` / `INIT SAFE` is refused.
PIN is **8–16 printable ASCII** (typed twice). Then `YES`.

Shared sequence:

1. `OWNER SET` then unsigned password + owner SPKI + SAE CA (skipped if already enrolled). Device SK is generated on-chip.
2. MANAGE `KEYGEN` (LAB leaves an occupied ECC slot alone, occupancy from `TROPIC PUB`; PROD may PIN-replace)
3. `MANAGE` KEM INIT with unsigned PIN
4. `CLIENT CSR` → write `client-csr.hex` next to the device cert

**LAB** then signs that CSR with `certs/ca/client_ca.p12` and installs the cert (`MANAGE CREDS DEVICE`, cert only). Pairing is not run; factory SH0 stays.

**PROD** does **not** use the lab client CA. It prints a production warning. TLS ENCRYPT/DECRYPT/PROVISION stay down until a client-CA-signed cert is present (`USERAPP_DEVICE_CERT`) and installed. Pairing slot **1–3** or **n**: MANAGE + PIN burns SH0; the pairing private key is never printed or saved.

KEM INIT stores the ML-KEM public key in NV.

## Lab USB

On silicon / a home PC this process opens `USB_SERIAL_PORT` and holds it.

In `./run-all.sh`, the **same** `userapp` tmux pane runs
`scripts/java.sh lab-userapp`. That wrapper starts this process only while
[LabSwitch](../LabSwitch/README.md) owner is `USER`, with `USB_SERIAL_PORT` set
to the selected client's PTY (`/tmp/ttyACM-se1` or `/tmp/ttyACM-se2`) and
`USERAPP_DEVICE_CERT` set to `client/` or `client2/`.
A client or owner change kills and restarts the JVM in that pane. This class does
not read the lab file.

Dump frames (`0xB1`) and ASCII `failed` from the device are not TLS. The TLS
stream starts at ClientHello `0x16` after dump/ASCII leftover is consumed.

## Prerequisites

- Java 21 and Maven (run from `JAVA_TLS_TEST`)
- User bundle from [CertGenerator](../CertGenerator/README.md)
  (`CERTGEN_CLIENTS` includes `otp-user`):
  - `certs/user/user.p12` (preferred) or `user-cert.pem` + `user-key.pem`
  - trust: `certs/ca/client_ca.pem` (`SoftwareTls.clientCaPem()`)
  - lab sign: `certs/ca/client_ca.p12`
- USB CDC ACM device (default `/dev/ttyACM0`); the app waits until it is present
- No HSM and no `env/hsm.env`

## How to run

```bash
cd JAVA_TLS_TEST
# optional: cp env/example/userapp.env.example env/userapp.env && set -a && source env/userapp.env && set +a

mvn -pl :user-app -am exec:java
```

Certificate directory defaults to `certs/`. Override with `PQC_CERTS_DIR` or
`-Dpqc.certs.dir=...`.

## Config

Template: [`env/example/userapp.env.example`](../../env/example/userapp.env.example).

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `USB_SERIAL_PORT` | no | `/dev/ttyACM0` | CDC ACM path |
| `USB_BAUD_RATE` | no | `115200` | Serial baud rate |
| `PQC_CERTS_DIR` | no | `certs` | Root of the cert tree |
| `USERAPP_OWNER_CERT` | no | `user/user-cert.pem` | Owner ML-DSA leaf if PKCS#12 is absent |
| `USERAPP_OWNER_KEY` | no | `user/user-key.pem` | Owner private key if PKCS#12 is absent |
| `USERAPP_OWNER_P12` | no | `user/user.p12` | Owner PKCS#12 (preferred TLS identity) |
| `USERAPP_OWNER_P12_PASSWORD` | no | `password` | PKCS#12 password |
| `USERAPP_DEVICE_CERT` | no | `client/client-cert.pem` | Signed device leaf installed by INIT LAB / CREDS DEVICE |
| `USERAPP_CLIENT_CA_P12` | no | `ca/client_ca.p12` | Lab client CA used by INIT LAB to sign `CLIENT CSR` |
| `USERAPP_SAE_CA` | no | `ca/root-ca.pem` | SAE root CA written into the chip on OWNER / INIT |

No HSM variables. This process never calls `Pqmi`.

## Source layout

```text
src/UserApp/
  README.md
  main/java/fel/cvut/userapp/        UserApplication, ChipService, OwnerAuth, PeerCertHash, ChipInit
  test/java/fel/cvut/userapp/        ChipInitTest, OwnerAuthTest, PeerCertHashTest
```

USB link (including `transact` / `readConsole`) lives in [TerminalBridge](../TerminalBridge/README.md).
OTP framing (`SecureOtp`, `SeBytes`) and software TLS (`SoftwareTls.createContextFromPem` /
`SoftwareTls.createContextFromPkcs12`) live in [SaeNode](../SaeNode/README.md) / `tls-software`.
Chip verbs: [COMMANDS.md](../../../stm32u535-trustzone-usb/docs/COMMANDS.md).
