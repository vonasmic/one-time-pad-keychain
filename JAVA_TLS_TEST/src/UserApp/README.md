# UserApp

**USER** application: USB console for the home-PC user. This is **not** an SAE.
The device connects to this process for OTP **encrypt / decrypt** and **MANAGE**
(INIT / OWNER / PEER / CREDS). Provision is a separate **SAE** path: the SAE
node plus [TerminalBridge](../TerminalBridge/README.md). This process does
**not** use the HSM: the user ML-DSA key is loaded from `certs/user/` into an
in-memory PKCS#12 store and Bouncy Castle JSSE signs in process. The user key is
never embedded in firmware.

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
| `LEFT` / `OTP LEFT` | USB `TROPIC OTP LEFT` — remaining/capacity pad kilobytes (`enc=A/B kb dec=C/D kb`), no PIN |
| `PEER ADD` | nickname + 96-hex peer hash + PIN → unsigned MANAGE TLS |
| `PEER LIST` / `PEER REMOVE` | LIST is USB; REMOVE is unsigned MANAGE TLS with PIN |
| `INIT` | Wizard: OWNER SET blob, KEYGEN, MANAGE KEM INIT, PAIRING (see below) |
| `OWNER` | Enroll this UserApp cert (`OWNER SET` unsigned blob + reset password + device creds) |
| `REPLACE` | `OWNER REPLACE` over unsigned MANAGE TLS (reset password, not M&D) |

USB command for OTP is `{MODE} {unix}`. After TLS this process is a loopback
TLS server over CDC. PIN for ENCRYPT/DECRYPT is **only inside TLS**.

`PEER ADD` takes a 96-hex SHA-384 of the peer SPKI (same width firmware stores). The UserApp certificate **is** the device owner key.

### Chip lines (passthrough)

Any line that is not an APP command is written to the chip and the
ASCII/`DEBUG:<text>:DEBUG` reply is printed — `HELP`, `TROPIC PING`, `CLIENT HASH`,
`TROPIC OTP LEFT`, … go straight to the firmware parser.

- `CLIENT HASH` prints the device `client_hash` (96 hex digits).
- `TROPIC OTP LEFT` prints remaining/capacity pad kilobytes (no PIN). Unprovisioned is `0/xx kb`.
- `PROVISION`, `ENCRYPT`, `DECRYPT`, and `MANAGE` are **refused** on passthrough: they switch the pipe
  to opaque TLS. Use APP ENCRYPT/DECRYPT/PEER/INIT, or TerminalBridge for provision.

### INIT

Prompts for a reset password, PIN (typed twice), pairing slot **1–3** or **n** to
leave pairing unchanged, then `YES`. Warnings cover losing the PIN, factory **SH0**
invalidation, replacing ECC slot 0, and occupied KEM slot 510. Sequence sent to the chip:

1. If `pairing.key` exists and you chose **n**: `TROPIC PAIRING LOAD` (restore MCU NV after a reflash; no Tropic write)
2. `OWNER SET` then unsigned password + owner SPKI + device cert/key + SAE CA from `USERAPP_*` env (skipped if already enrolled)
3. `TROPIC KEYGEN` (if occupied, MANAGE TLS with unsigned PIN)
4. `MANAGE` KEM INIT with unsigned PIN (ASCII digits, same as ENCRYPT)
5. If you chose **1–3**: `TROPIC PAIRING <slot>` then `TROPIC PAIRING <slot> y`; save `TROPIC PAIRING KEY` to `pairing.key`. **n** skips this.

`TROPIC KEYGEN` is P-256 ECC slot 0 (signing). Factory SH0 is pairing slot 0
(X25519) and is replaced by PAIRING — the app does not copy the ECC key into SH0.
Successful PAIRING prints `TROPIC PAIRING KEY` and the app writes `pairing.key`
next to the device cert (`certs/client/pairing.key` by default, or
`USERAPP_PAIRING_KEY`). After an MCU reflash, INIT with **n** LOADs that file **before**
KEYGEN, because SH0 is already burned. Use **n** whenever you do not want a new Tropic pairing key.

Stops if a probe fails; does not send CONFIRM / `y` after a failed step.

KEM INIT stores the ML-KEM public key in NV (no reflash). `OWNER` / `INIT` write the
UserApp owner SPKI plus device cert/key and SAE CA in the `OWNER SET` blob. That is
enough for PROVISION/ENCRYPT/DECRYPT; CREDS SAE / CREDS DEVICE are MANAGE TLS commands
used by other enroll paths, not a UserApp USB step.

## Lab USB

On silicon / a home PC this process opens `USB_SERIAL_PORT` and holds it.

In `./run-all.sh`, the **same** `userapp` tmux pane runs
`scripts/java.sh lab-userapp`. That wrapper starts this process only while
[LabSwitch](../LabSwitch/README.md) owner is `USER`, with `USB_SERIAL_PORT` set
to the selected client's PTY (`/tmp/ttyACM-se1` or `/tmp/ttyACM-se2`) and
`USERAPP_DEVICE_CERT` / `USERAPP_DEVICE_KEY` set to `client/` or `client2/`.
A client or owner change kills and restarts the JVM in that pane. This class does
not read the lab file.

`DEBUG:<text>:DEBUG` frames from the device are printed (wrapper stripped on console transact)
and never treated as TLS. The TLS stream starts at ClientHello `0x16` after `:DEBUG`.

## Prerequisites

- Java 21 and Maven (run from `JAVA_TLS_TEST`)
- User bundle from [CertGenerator](../CertGenerator/README.md)
  (`CERTGEN_CLIENTS` includes `otp-user`):
  - `certs/user/user-cert.pem`
  - `certs/user/user-key.pem`
  - trust: `certs/ca/client_ca.pem` (`NodeTls.clientCaPem()`)
- USB CDC ACM device (default `/dev/ttyACM0`); the app waits until it is present
- No HSM and no `env/hsm.env`

## How to run

```bash
cd JAVA_TLS_TEST
# optional: cp env/example/userapp.env.example env/userapp.env && set -a && source env/userapp.env && set +a

mvn exec:java -Dexec.mainClass=fel.cvut.userapp.UserApplication
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
| `USERAPP_OWNER_CERT` | no | `user/user-cert.pem` | Owner ML-DSA leaf (TLS + OWNER SET SPKI) |
| `USERAPP_OWNER_KEY` | no | `user/user-key.pem` | Owner private key |
| `USERAPP_DEVICE_CERT` | no | `client/client-cert.pem` | Device leaf written into the chip |
| `USERAPP_DEVICE_KEY` | no | `client/client-key.pem` | Device private key written into the chip |
| `USERAPP_PAIRING_KEY` | no | next to the device cert: `pairing.key` | Host backup of Tropic X25519 pairing priv/pub |
| `USERAPP_SAE_CA` | no | `ca/root-ca.pem` | SAE root CA written into the chip on OWNER / INIT |

No HSM variables. This process never calls `Pqmi`.

## Source layout

```text
src/UserApp/
  README.md
  main/java/fel/cvut/userapp/        UserApplication, OwnerAuth, PeerCertHash, ChipInit
  test/java/fel/cvut/userapp/        PeerCertHashTest
```

USB link (including `transact` / `readConsole`) lives in [TerminalBridge](../TerminalBridge/README.md).
OTP framing (`SecureOtp`, `SeBytes`) and software-PEM TLS (`NodeTls.createContextFromPem`)
live in [SaeNode](../SaeNode/README.md).
Chip verbs: [COMMANDS.md](../../../stm32u535-trustzone-usb/docs/COMMANDS.md).
