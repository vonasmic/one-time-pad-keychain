# Domain

QKD-backed one-time-pad **keychain**: a TrustZone STM32U535 **device** stores pads on TROPIC01.
The device is a TLS client. Two host processes own USB CDC, one at a time:

- **USER** — UserApp: encrypt / decrypt / manage. Not an SAE.
- **SAE** — SaeNode, usually via TerminalBridge: provision / QKD fill.

## Owner

The enrolled UserApp ML-DSA key. First USB **OWNER SET** wins (unsigned blob:
reset password + owner SPKI + optional SAE CA). Later identity changes go over
**MANAGE**. Device ML-DSA is generated on-chip.

## MANAGE

Owner-pinned TLS (no device client cert). One unsigned command per session:
KEM INIT, KEYGEN, PEER ADD/REMOVE, CREDS, OWNER REPLACE, PAIRING.

Mutating Tropic ops (KEYGEN, KEM INIT, pairing, peer changes) go only
through MANAGE. USB keeps read-only dumps: PING, INFO, PUB, KEM PUB, OTP STATUS,
PEER LIST, CLIENT HASH/CSR.

USB errors are the single ASCII line `failed`. Dump status is occupancy/protocol
only (`ok` / `err` / `empty` / `refused`) — Tropic, TLS, and auth failure types
are not on USB.

Chip enrollment is one UserApp sequence (`ChipInit.enroll`): OWNER SET → MANAGE
KEYGEN → MANAGE KEM INIT → CLIENT CSR (LAB signs and INSERT SIGNED CSR; PROD dumps
CSR only) → optional PAIRING. After an external CA signs, the operator runs
INSERT SIGNED CSR. `OwnerAuth` is the USB/TLS chip port.

The Java **owner-manage wire codec** (`fel.cvut.se.SeManage`) is the encode/decode
locality for OWNER SET and MANAGE frames. USB/TLS session stays in UserApp.
Firmware peer is `se_manage.c` (`se_manage_owner_set_need` / `se_manage_req_need` /
`se_manage_rsp_encode`). `se_auth.c` only drains USB into that codec, then applies
`se_owner_set`.
