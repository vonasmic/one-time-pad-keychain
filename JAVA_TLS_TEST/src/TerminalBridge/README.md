# TerminalBridge

Standalone operator console for a running [SaeNode](../SaeNode/README.md). It answers
SELECT / CONFIRM / NOTIFY over TLS instead of blocking inside the node on stdin.

Optionally it also relays USB CDC from the embedded device to the node's command
server (`UsbTcpBridge`). The node itself has no USB awareness.

Entry point: `fel.cvut.terminalapp.TerminalApp`.

Working directory must be `JAVA_TLS_TEST` (so `certs/` and `env/` resolve).

## What it does

- Connects to `NODE_HOSTNAME:NODE_TERMINAL_PORT` using the **same TLS bootstrap nodes
  use for RMI**: `NodeTls.createContextForNode` (HSM identity) + `PURE_PQC`
- Authenticates as a provisioned node identity (`certs/{TLS_NODE_ID}.pem`, typically
  `Terminal`) — not a bespoke client cert
- Implements `OperatorConsole` locally via stdin (`LocalOperatorConsole`)
- Speaks newline-delimited JSON (`TerminalWireProtocol`) with the node's `TerminalGateway`
- Keeps one long-lived operator-gateway TLS session; reconnects only after it ends or the node is unreachable
- If `USB_BRIDGE=1`, opens the serial port and relays TLS (from ClientHello `0x16`) to
  `NODE_HOSTNAME:NODE_NATIVE_PORT`, sending `PROVISION <unix>` when the device speaks.
  Framed `DEBUG:<text>:DEBUG` status from the device is printed, not forwarded.

Lab CL 1 / CL 2 is **not** handled here. `./run-all.sh` runs
`scripts/java.sh lab-terminal` in the same tmux pane, which restarts this process
with new `USB_SERIAL_PORT` / `NODE_*` when the lab file changes.

## Prerequisites

- Java 21 and Maven (run from `JAVA_TLS_TEST`)
- Utimaco vendor tree: `vendor/pqmi-java/`, `vendor/securityserver-jce.jar`, `vendor/cryptoservercxi.jar`
- HSM simulator or cHSM up — one-time init is in the
  [JAVA_TLS_TEST README — HSM setup](../../README.md#hsm-setup)
- Terminal identity provisioned by [CertGenerator](../CertGenerator/README.md)
  (`CERTGEN_NODES` includes `Terminal`, or whatever `TLS_NODE_ID` you use)
- A [SaeNode](../SaeNode/README.md) already listening on `NODE_TERMINAL_PORT`
- For USB relay: a CDC ACM device (default `/dev/ttyACM0`) and `NODE_NATIVE_PORT`

## How to run

```bash
cd JAVA_TLS_TEST
cp env/example/hsm.env.example env/hsm.env                # once; do not commit the PIN
cp env/example/terminal.env.example env/terminal-1.env    # once; match the target node

set -a
source env/hsm.env
source env/terminal-1.env
set +a
mvn exec:java -Dexec.mainClass=fel.cvut.terminalapp.TerminalApp
```

`env/hsm.env` must be **sourced**. You can also export the variables by hand.

Without the built-in USB pump, an external relay works the same way:

```bash
socat -d -d /dev/ttyACM0,b115200,raw,echo=0,crtscts=0 TCP:127.0.0.1:11111
```

## Config — `env/terminal-N.env`

Template: [`env/example/terminal.env.example`](../../env/example/terminal.env.example).

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `TLS_NODE_ID` | **yes** | — | HSM identity used to authenticate to the node (`certs/{TLS_NODE_ID}.pem`) |
| `NODE_HOSTNAME` | **yes** | — | Hostname of the node to operate |
| `NODE_TERMINAL_PORT` | **yes** | — | That node's terminal gateway port |
| `USB_BRIDGE` | no | off | `1` / `true` / `yes` / `on` enables the built-in USB↔TCP pump |
| `NODE_NATIVE_PORT` | if `USB_BRIDGE=1` | — | Node TLS command server |
| `USB_SERIAL_PORT` | no | `/dev/ttyACM0` | CDC ACM path |
| `USB_BAUD_RATE` | no | `115200` | Serial baud rate |

HSM connection (`HSM_DEVICE`, `HSM_USER`, `HSM_PIN`, …) comes from `env/hsm.env`, same
as for a node. See [`env/example/hsm.env.example`](../../env/example/hsm.env.example).

## Source layout

```text
src/TerminalBridge/
  README.md
  main/java/fel/cvut/terminalapp/   TerminalApp, UsbTcpBridge
  main/java/fel/cvut/terminal/      OperatorConsole, wire protocol, stdin UI
  main/java/fel/cvut/usb/           SeUsbLink, StreamSocket (CDC ACM)
```

TLS / HSM helpers live in [SaeNode](../SaeNode/README.md). Provision USB relay is this
app only; [UserApp](../UserApp/README.md) is ENCRYPT / DECRYPT.
