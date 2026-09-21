# API

USB CDC console for the **current** SE firmware in [`stm32u535-trustzone-usb/`](stm32u535-trustzone-usb/README.md).

Authoritative tables: [`stm32u535-trustzone-usb/docs/COMMANDS.md`](stm32u535-trustzone-usb/docs/COMMANDS.md).
TLS / LV framing: [`docs/COMMUNICATION.md`](stm32u535-trustzone-usb/docs/COMMUNICATION.md).

The device appears as USB CDC ACM (`/dev/ttyACM*` on Linux). Lines end with `\n` (`\r` ignored). Max line **160** characters. `HELP` (or `?`) lists names.

PIN for provisioned OTP never appears on the ASCII line. Arm a mode and a Unix time; PIN and payloads ride inside TLS after the handshake. **SAE** is the TLS peer for `PROVISION`. **USER** (UserApp) is the TLS peer for `ENCRYPT` / `DECRYPT` / `MANAGE`.

## Top-level commands

| Syntax | What it does |
| --- | --- |
| `HELP` | Print usage lines |
| `OWNER SET` | First-wins unsigned blob (password + owner SPKI + optional SAE CA) |
| `PROVISION <unix>` | Arm TLS mode 1 (**SAE**: mTLS provision, uplink v4, downlink v2) |
| `ENCRYPT <unix>` | Arm TLS mode 2 (**USER**: owner-pinned mTLS encrypt) |
| `DECRYPT <unix>` | Arm TLS mode 3 (**USER**: owner-pinned mTLS decrypt) |
| `MANAGE <unix>` | Arm TLS mode 4 (**USER**: owner-pinned, no device client cert; KEM INIT / KEYGEN / PEER / CREDS / OWNER REPLACE / PAIRING) |
| `PEER LIST` | Print NV peers |
| `CLIENT HASH` | 96 hex digits: `SHA384(device_cert_spki \|\| ecc_pub)` |
| `TROPIC PING` / `INFO` / `PUB` / `KEM PUB` / `OTP LEFT` | Tropic / OTP console |

`<unix>` is a non-zero decimal Unix UTC timestamp.
