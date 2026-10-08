# TerminalBridge

Standalone **SAE** operator console for a running [SaeNode](../SaeNode/README.md). It answers
SELECT / CONFIRM / NOTIFY over TLS instead of blocking inside the node on stdin.

It also relays USB CDC from the embedded device to the node's command server
(`UsbTcpBridge`) for **PROVISION**. The node itself has no USB awareness.
This is not UserApp: encrypt / decrypt / manage stay on [UserApp](../UserApp/README.md).

Entry point: `fel.cvut.terminalapp.TerminalApp`.

Working directory must be `JAVA_APPS` (so `certs/` and `env/` resolve).

## What it does

- Connects to `NODE_HOSTNAME:NODE_TERMINAL_PORT` using the **same TLS bootstrap nodes
  use for RMI**: `HsmNodeTls.createContextForNode` (HSM identity) + `PURE_PQC`
- Authenticates as a provisioned node identity (`certs/{TLS_NODE_ID}.pem`, typically
  `Terminal`) — not a bespoke client cert
- Implements `OperatorConsole` locally via stdin (`LocalOperatorConsole`)
- Speaks newline-delimited JSON (`TerminalWireProtocol`) with the node's `TerminalGateway`
- Keeps one long-lived operator-gateway TLS session; reconnects only after it ends or the node is unreachable
- Always starts the USB bridge: sends `PROVISION <unix>` on the serial port, then
  runs a **dumb** USB↔TCP byte pipe to `NODE_HOSTNAME:NODE_NATIVE_PORT` (no
  ClientHello / dump demux — same idea as `socat`).

Lab CL switching is gone. `./run-all.sh` runs `scripts/java.sh lab-terminal 1`
and `lab-terminal 2` in fixed panes so both operator gateways stay up (concurrent
key-get sync). The lab wrapper toggles `USB_SERIAL_PORT` (`none` vs the client PTY)
when owner is SAE — both terminals get USB together.

## Prerequisites

- Java 21 and Maven (run from `JAVA_APPS`)
- Utimaco vendor tree: `vendor/pqmi-java/`, `vendor/securityserver-jce.jar`, `vendor/cryptoservercxi.jar`
- HSM simulator or cHSM up — one-time init is in the
  [JAVA_APPS README — HSM setup](../../README.md#hsm-setup)
- Terminal identity provisioned by [CertGenerator](../CertGenerator/README.md)
  (`CERTGEN_NODES` includes `Terminal`, or whatever `TLS_NODE_ID` you use)
- A [SaeNode](../SaeNode/README.md) already listening on `NODE_TERMINAL_PORT`
- A CDC ACM device (default `auto`, which scans for the keychain) and `NODE_NATIVE_PORT` for the USB↔TCP pipe

## How to run

```bash
cd JAVA_APPS
cp env/example/hsm.env.example env/hsm.env                # once; do not commit the PIN
cp env/example/terminal.env.example env/terminal-1.env    # once; match the target node
# For SAE 2 also: env/terminal-2.env (ports 11113 / 5020 / ttyACM-se2)

set -a
source env/hsm.env
source env/terminal-1.env
set +a
mvn -pl :terminal-bridge -am exec:java
```

Or `scripts/java.sh terminal env/terminal-2.env`. `env/hsm.env` must be **sourced**.
You can also export the variables by hand.

## Config — `env/terminal-N.env`

Template: [`env/example/terminal.env.example`](../../env/example/terminal.env.example).

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `TLS_NODE_ID` | **yes** | — | HSM identity used to authenticate to the node (`certs/{TLS_NODE_ID}.pem`) |
| `NODE_HOSTNAME` | **yes** | — | Hostname of the node to operate |
| `NODE_TERMINAL_PORT` | **yes** | — | That node's terminal gateway port |
| `NODE_NATIVE_PORT` | **yes** | — | Node TLS command server (USB↔TCP pump destination) |
| `USB_SERIAL_PORT` | no | `auto` | CDC path, or `auto` / `scan` to find the keychain (`0483:5710`); `none` / `off` / `disabled` skips the USB bridge |
| `USB_BAUD_RATE` | no | `115200` | Serial baud rate |

HSM connection (`HSM_DEVICE`, `HSM_USER`, `HSM_PIN`, …) comes from `env/hsm.env`, same
as for a node. See [`env/example/hsm.env.example`](../../env/example/hsm.env.example).

## Source layout

```text
src/TerminalBridge/
  README.md
  main/java/fel/cvut/terminalapp/   TerminalApp, UsbTcpBridge
  main/java/fel/cvut/terminal/      OperatorConsole, wire protocol, stdin UI
  main/java/fel/cvut/usb/           SeUsbLink (CDC ACM; shared via usb-cdc)
```

TLS / HSM helpers live in [SaeNode](../SaeNode/README.md). Provision USB relay is this
app only; [UserApp](../UserApp/README.md) is INIT / OWNER / PEER / ENCRYPT / DECRYPT
(and chip passthrough).
