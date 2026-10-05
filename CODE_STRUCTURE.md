# Code structure

QKD-backed OTP keychain: TrustZone STM32U535 firmware with TROPIC01, plus two Java
applications the device talks to over USB CDC — **USER** (UserApp) and **SAE**
(SaeNode, usually via TerminalBridge).

## Host apps the device connects to

The firmware is a TLS **client**. Only one host process may own CDC at a time.

| App | Process | TLS modes | Role |
| --- | --- | --- | --- |
| **USER** | [`UserApp`](JAVA_APPS/src/UserApp/README.md) | `ENCRYPT` / `DECRYPT` / `MANAGE` | Home-PC console: OTP consume, INIT / OWNER / PEER. Not an SAE. |
| **SAE** | [`SaeNode`](JAVA_APPS/src/SaeNode/README.md) via [`TerminalBridge`](JAVA_APPS/src/TerminalBridge/README.md) USB relay | `PROVISION` | QKD fill (uplink v4 / downlink v2). Operator SELECT/CONFIRM stays on the terminal gateway, not UserApp. |

Do not write “device ↔ SAE” for encrypt, decrypt, or manage — those sessions are
device ↔ USER. Provision is the SAE path.

## Current trees

| Path | Role |
| --- | --- |
| JAVA_APPS | Maven reactor: `se-wire`, `usb-cdc`, `tls-software`, `tls-hsm`, `cert-generator`, `user-app`, `sae-node`, `terminal-bridge`, `lab-switch` |
| [`stm32u535-trustzone-usb/`](stm32u535-trustzone-usb/README.md) | CubeIDE `SE_firmware`: Secure (wolfSSL TLS, Tropic SPI, NV) + NonSecure (USB CDC parser) |
| [`stm32u535-trustzone-usb/host/`](stm32u535-trustzone-usb/host/README.md) | `se_host` PTY device + Tropic `model_server` tests A–K |
| [`diagrams/`](diagrams/) | draw.io architecture and provision-flow figures |
| [`scripts/`](scripts/) | `run-all.sh`, `java.sh`, `host.sh`, `hsm.sh` |
| [`ultimaco/`](ultimaco/hsm-simulator/README.md) | Drop-in HSM / Quantum Protect SDKs |

Firmware docs: [`docs/COMMANDS.md`](stm32u535-trustzone-usb/docs/COMMANDS.md), [`docs/COMMUNICATION.md`](stm32u535-trustzone-usb/docs/COMMUNICATION.md), [`docs/TROPIC.md`](stm32u535-trustzone-usb/docs/TROPIC.md), [`docs/HARDWARE.md`](stm32u535-trustzone-usb/docs/HARDWARE.md).

## Diagrams (`diagrams/`)

Open in [diagrams.net](https://app.diagrams.net/).

| File | What it shows |
| --- | --- |
| [`SAE_diagram.drawio`](diagrams/SAE_diagram.drawio) | **SAE / provision** path only: SE over USB CDC, TerminalApp / UsbTcpBridge, Node ports (`NODE_TERMINAL_PORT`, `NODE_NATIVE_PORT`, RMI), peer SAE, KME / QKD, Utimaco HSM, SQLite. UserApp is not on this figure. |
| [`SE_diagram.drawio`](diagrams/SE_diagram.drawio) | TrustZone USB stack: Host CDC, NonSecure USBX + `tls_usb_io.c`, Secure wolfSSL / NSC, FLASH_CREDS page 21, FLASH_NV page 22, TROPIC01 slots 0–511 |
| [`provision_flow.drawio`](diagrams/provision_flow.drawio) | PROVISION decision tree (device ↔ SAE): uplink verify, `startRecordInsert` (including stale in-progress reclaim), peer insert, ingest, operator prompts |

## Java packages (`JAVA_APPS/src`)

| App | Packages | Role |
| --- | --- | --- |
| SaeNode | `fel.cvut.node`, `db`, `qkd`, `se`, `tls`, `utimaco` | **SAE** |
| CertGenerator | `fel.cvut.certGen` | PKI / HSM |
| TerminalBridge | `fel.cvut.terminalapp`, `terminal`, `usb` | SAE operator + USB relay |
| UserApp | `fel.cvut.userapp` | **USER** |
| LabSwitch | `fel.cvut.lab` | lab CDC owner |

Working directory for Maven is `JAVA_APPS` so `certs/` and `env/` resolve.

## Firmware (`stm32u535-trustzone-usb`)

```text
Secure/           TLS client, Tropic, MCU NV, NSC
NonSecure/        USBX CDC ACM + command parse (`tls_usb_io.c`)
Secure_nsclib/    NSC headers
host/             model tests + se_host
docs/             HOW_TO_RUN, COMMANDS, COMMUNICATION, TROPIC, SECURITY, HARDWARE
```

Boot: Secure init, jump to NonSecure at `0x08030000`, USB enumerates as CDC ACM. After `PROVISION` (SAE) / `ENCRYPT` / `DECRYPT` / `MANAGE <unix>` (USER), the same CDC pipe carries TLS bytes to Secure.
