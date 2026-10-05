# One-time-pad keychain

QKD-backed one-time-pad keychain: a TrustZone STM32U535 device stores pads on TROPIC01.
The device is a TLS client and connects to **two** Java applications over USB CDC:
**USER** (UserApp: encrypt / decrypt / manage) and **SAE** (SaeNode via TerminalBridge:
provision / QKD fill). UserApp is not an SAE.

## Contents

- [Layout](#layout)
- [Lab stack](#lab-stack)
- [Firmware](#firmware)
- [Java applications](#java-applications)
- [Requirements](#requirements)
- [License](#license)

## Layout

| Path | Role |
| --- | --- |
| [`JAVA_APPS/`](JAVA_APPS/README.md) | SaeNode (SAE), UserApp (USER), TerminalBridge, CertGenerator, LabSwitch |
| [`stm32u535-trustzone-usb/`](stm32u535-trustzone-usb/README.md) | Current SE firmware (CubeIDE `SE_firmware`) + host `se_host` |
| [`ultimaco/`](ultimaco/hsm-simulator/README.md) | Drop-in location for Utimaco HSM + Quantum Protect SDKs |
| [`scripts/`](scripts/) | `run-all.sh`, `java.sh`, `host.sh`, `hsm.sh` |

USB console syntax: [`stm32u535-trustzone-usb/docs/COMMANDS.md`](stm32u535-trustzone-usb/docs/COMMANDS.md). TLS / LV framing: [`docs/COMMUNICATION.md`](stm32u535-trustzone-usb/docs/COMMUNICATION.md).

## Lab stack

Start the Windows HSM simulator yourself (`cs_sim.bat` — [JAVA_APPS HSM setup](JAVA_APPS/README.md#hsm-setup)). Then from this repo root:

```bash
./run-all.sh
```

That builds `se_host`, migrates the node databases, and opens a tmux session with two Tropic models, two SAE nodes, TerminalBridge, UserApp, LabSwitch, and two simulated keychains. Details: [`RUN_ALL.md`](RUN_ALL.md).

## Firmware

Silicon (TS13 DevKit): CubeIDE build and flash — [`stm32u535-trustzone-usb/docs/HOW_TO_RUN.md`](stm32u535-trustzone-usb/docs/HOW_TO_RUN.md).

Host model (no board): [`stm32u535-trustzone-usb/host/README.md`](stm32u535-trustzone-usb/host/README.md).

The device enumerates as USB CDC ACM. Arm TLS with `PROVISION` (SAE) / `ENCRYPT` / `DECRYPT` / `MANAGE <unix>` (USER) — PIN and payloads ride inside TLS after the handshake. `HELP` lists console names.

## Java applications

**USER** = [`UserApp`](JAVA_APPS/src/UserApp/README.md). **SAE** = [`SaeNode`](JAVA_APPS/src/SaeNode/README.md) plus [`TerminalBridge`](JAVA_APPS/src/TerminalBridge/README.md) for the USB relay. They are different processes; only one may open CDC.

Working directory for Maven is `JAVA_APPS` (so `certs/` and `env/` resolve). Wrappers from the repo root:

```bash
scripts/java.sh certgen
scripts/java.sh node env/node-1.env
scripts/java.sh terminal
scripts/java.sh userapp
```

Or source `env/hsm.env` plus the process env file and run `mvn exec:java` as documented in each app README.

## Requirements

- Java 21, Maven, SQLite (local file per SAE node)
- Python 3, cmake, a C compiler, make, tmux, git (lab stack)
- STM32CubeIDE + STM32CubeProgrammer (silicon)
- Utimaco SDKs under `ultimaco/` and JCE jars under `JAVA_APPS/vendor/` (not committed)

## License

See [`LICENSE.txt`](LICENSE.txt).
