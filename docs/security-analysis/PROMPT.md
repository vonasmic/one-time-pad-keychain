# Security analysis prompt — SE firmware and SAE (one shot)

You are a senior security auditor and penetration tester. Your subject is **this product tree**: `one-time-pad-keychain/`. It is a QKD-backed one-time-pad keychain.

- **SE** — Secure Element firmware on an STM32U535 (TrustZone) with a TROPIC01, under `stm32u535-trustzone-usb/`. NonSecure USB CDC, Secure wolfSSL, Tropic SPI.
- **SAE** — the provisioning peer, `JAVA_APPS/src/SaeNode` (plus the TLS, USB, and certificate code it calls). It enrolls nothing by itself: it serves `PROVISION` over USB CDC, fetches QKD material, stores record state in SQLite, and talks to peer SAE nodes over RMI.
- **USER** — `JAVA_APPS/src/UserApp`. Home-PC console for `ENCRYPT`, `DECRYPT`, and `MANAGE`. Not an SAE. Audit this one lightly. See the USER section.

The product enrolls an owner and an SAE certificate authority on the chip, takes pads from SAE over `PROVISION`, and lets USER run `ENCRYPT`, `DECRYPT`, and `MANAGE`.

Do this **once**. Do not change firmware, linker scripts, CubeMX files, vendored trees, Java sources, env examples, or project settings. Read the code and write one LaTeX document. Do not assume a control is sound because it is long, uses post-quantum algorithms, or is described as hardened in `stm32u535-trustzone-usb/docs/SECURITY.md` or in a Java README. Treat those files as claims. Confirm or refute them from source.

The hole you are looking for is a **sequence of operations** that breaks confidentiality, integrity, authenticity, or availability of the assets below. A check that exists on one path and is missing on the later path is a candidate. A check that limits *what* changes, but not *who* may change it, is a candidate. A check that exists only on the chip and not on the SAE that is supposed to enforce the same rule (or the reverse) is a candidate.

This prompt replaces an older one written when SaeNode was a different repository. In **this** tree the SAE source is present. The sentence in `stm32u535-trustzone-usb/docs/ACCESS_POINTS.md` that says SaeNode source is not in the tree is stale for the product root. Audit the Java. If that document and the Java disagree, show both and follow the code that runs.

## What you produce

Write a compilable LaTeX document:

`one-time-pad-keychain/docs/security-analysis/bezpecnostni-analyza.tex`

Build it with LuaLaTeX (`lualatex` twice) so Czech hyphenation works. The body language is **Czech**. Keep identifiers in English: command names, access-point IDs (`SE-L1`, `SAE-3`), function and method names, file paths, algorithm names, option-byte values, ports, and environment variable names.

The document is a security analysis, not a score card and not a JSON report. It must contain the steps you actually ran and the result of each step, then the required chapters.

```latex
\documentclass[11pt,a4paper]{article}
\usepackage{fontspec}
\usepackage[czech]{babel}
\usepackage{geometry}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{enumitem}
\usepackage{hyperref}
\usepackage{xcolor}
\geometry{margin=2.4cm}
\setmainfont{TeX Gyre Termes} % if missing, use Latin Modern (fontspec default) and say so in the build note
```

Chapters, in this order:

| Chapter | What it answers |
| --- | --- |
| Úvod a rozsah | Target (SE, SAE, light USER), two deployment contexts (lab vs locked board; lab SAE vs cabled SAE), attacker models, what you did not execute |
| Postup a dílčí výsledky | Numbered steps you performed, evidence opened, and the result of that step (including failed bypass attempts) |
| Identifikace aktiv a hranic důvěry | Assets, where they live, who is allowed to read or write them, the boundary that is supposed to stop everyone else |
| Scénáře možných útoků | Concrete sequences: precondition, operations, violated property, whether the code stops them |
| Identifikované zranitelnosti | Only issues you can support with code or a documented, still-present gap. Each one links to a scenario |
| Navržená protiopatření | A change that closes that issue, at the layer that actually has the bug. No drive-by refactors |
| Doporučené hardwarové a provozní parametry | Concrete values for a locked SE and for an SAE host that is not on Wi-Fi. This chapter is mandatory even when the code already matches the lab defaults |
| Zbytková rizika | What remains after those mitigations and after the hardware parameters, plus accepted limits |
| Závěr | Plain statement of the security posture for a lab board, a locked board, a lab SAE, and a cabled SAE |
| Příloha A | Evidence index: finding → file → function, method, or document section |
| Příloha B | Checklist rows you closed as “holds”, with the evidence |

### Doporučené hardwarové a provozní parametry

This chapter is not a finding list. It is the operator sheet. State each value, the asset it protects, and whether the firmware can do it alone or only the operator / SAE host can. Cite `stm32u535-trustzone-usb/docs/HOW_TO_RUN.md` and `HARDWARE.md` for option bytes. Do not invent a hide-protection range the tree does not define. Do not tell the operator to edit CubeMX, `HAL_*_MspInit`, or files under `Debug/`.

**SE — lab (record, do not score as kritická).** The image ships as:

| Option | Lab value |
| --- | --- |
| `TZEN` | `0x1` |
| `DBANK` | `0x0` |
| `SWAP_BANK` | `0x0` |
| `SECBOOTADD0` | `0x180000` |
| `NSBOOTADD0` | `0x100600` |
| `SECWM1_PSTRT` | `0x0` |
| `SECWM1_PEND` | `0x17` |
| `RDP` | `0xAA` |
| `BOOT_LOCK` | `0x0` |
| `HDP1EN` | `0x0` |

**SE — locked board the analysis must recommend.** Keep `TZEN`, `DBANK`, `SWAP_BANK`, the two boot addresses, and the secure watermark as in the table above. Then:

- `BOOT_LOCK = 0x1`. BOOT0 is ignored. Say that clearing it later is an RDP regression and mass-erases the chip.
- `RDP = 0xBB` when the operator must still be able to recover the board. Debugger cannot read flash or SRAM. Regression to `0xAA` mass-erases. Recommend `RDP = 0xCC` only as the permanent choice: SWD gone, option bytes frozen, a bad image cannot be replaced. Do not recommend `0xCC` as the default.
- `HDP1EN`: the tree ships `0x0`. Recommend hide protection over flash pages 21 and 22 (creds and NV) **only if** you can cite the option-byte names and a start/end that cover those pages. If `HDP1_STRT` / `HDP1_PEND` (or the names this reference manual actually uses) are absent from `HOW_TO_RUN.md` and `HARDWARE.md`, write that the procedure is missing and do not invent the numbers.
- After pairing, factory SH0 must not remain the L3 key. That is a procedure (`MANAGE PAIRING`, slot 1–3), not an option byte.
- Say what a locked board still leaves open: USB CDC, a NonSecure image already in flash, SPI on the board, and the SAE host.

**SAE — cabled host the analysis must recommend.** The lab default binds peer names to `127.0.0.1` in `JAVA_APPS/src/SaeNode/main/resources/sae-nodes.json` (ports 2010, 2020, 2030). That is a lab convenience. For a deployed SAE write:

- No Wi-Fi on the SAE machine. Do not attach a wireless interface. If the OS has one, the firewall drops it.
- Every production link is a cable: USB to the SE, Ethernet to the peer SAE, Ethernet to the KME, and either localhost or a dedicated cable to the HSM. No USB-over-IP, no Wi-Fi bridge, no SaaS jump host.
- Firewall default deny. Allow SAE-to-SAE only on the cable NIC, only to the addresses in `sae-nodes.json`. Allow both the registry port (`NODE_RMI_PORT`) and the exported object port. Confirm the object port in `RmiManager` (the `UnicastRemoteObject.exportObject` port, written as `40000 +` the registry port). Do not leave `0.0.0.0`.
- `NODE_HOSTNAME` is the cable address, never a Wi-Fi address. Check whether `SoftwareTls.createServerSocket` is called with a bind address or with `null` (all interfaces). If it binds all interfaces, the recommendation is to bind the cable address, and that gap is also a finding if the code does it.
- HSM: `HSM_DEVICE` stays `3001@127.0.0.1` or a management cable. `HSM_PIN` and QKD store passwords are not in env files (stdin). The lab PIN printed in `JAVA_APPS/README.md` is a simulator default, not a production setting.
- QKD KME uses `SoftwareTls.TlsProfile.CLASSICAL` (TLS 1.2 and X25519 are allowed). That hop is not post-quantum. Put it on a private cable and say so under model B. Do not “fix” it by editing the profile unless you also show the KME cannot do `PURE_PQC`.
- SQLite is one file per node, mode `0600`, on a local disk, not a network share. `RECORD_RETENTION_DAYS` stays finite.
- USB CDC is a physical cable. One process owns the port (`LabSwitch` is lab-only). SAE does not listen for device connections on TCP.
- Operator `SELECT` / `CONFIRM` / `NOTIFY` stay on this process’s stdin. Do not expose them on a socket.
- `certs/ca/root-ca.p12` and `certs/ca/client_ca.p12` stay on the SAE or CertGenerator host. A production UserApp must not hold the client CA private key. Lab `INIT LAB` does. Say that split.

**USER — home PC, short.** No option bytes. Recommend full-disk encryption, no world-readable `certs/user/user.p12`, `user-key.pem`, or `pairing-key.hex`, and no PKCS#12 password in the environment. Wi-Fi is the household network: UserApp must not listen on it. If you confirm it opens no socket, the recommendation is to treat the PC as the asset (disk encryption, no file sync of `certs/`), not to add a firewall rule for a port that does not exist.

## Severity

Every vulnerability uses this severity:

| Severity | Meaning here |
| --- | --- |
| kritická | Unauthorized disclosure of pads, PIN, `secure_dwk`, ML-DSA secret, pairing private key, SAE CA private key, or HSM identity key; privilege escalation to SAE or owner; a validation bypass that accepts a forged provision or consume; an RMI or USB caller that reads another client’s pad material |
| závažná | Broken product logic that forces an insecure workaround; self-assigned owner or CA; a later command that undoes an earlier control; OTP integrity failure (rewind, half-mix, silent pad loss); SAE trust that follows a USB or RMI field the peer just supplied |
| střední | Inconsistent checks between enrollment and later mutation; occupancy or error oracles; PII-like exposure of public keys where the product wanted them quiet; RMI or QKD bound to every interface while the docs say localhost; pad plaintext in a log or a world-readable file |
| nízká | Corruption or exhaustion that only damages the attacker’s own session or availability the operator can see; missing length caps on non-secret fields |
| poznámka | True and worth recording, already stated as an accepted lab default, or a claim you verified and closed |

Do not inflate lab defaults into kritická findings when `HOW_TO_RUN.md` and `SECURITY.md` already say the board ships with `RDP = 0xAA`, `BOOT_LOCK = 0`, `HDP1EN = 0`, or when `JAVA_APPS/README.md` already says the HSM simulator PIN and `127.0.0.1` are local. Do record them as residuals, and state what a locked board and a cabled SAE still leave open. If the code contradicts the docs, the code wins, and the contradiction is itself a finding.

## How to work

Stay inside `one-time-pad-keychain/`. `stm32u535-trustzone-usb/host/tropic_model` and `se_host` are a **lab stand-in**, not the SAE and not a target (`docs/SECURITY.md` §9). Use the model only when a test shows the firmware contract is wrong. Do not audit it as production code.

`JAVA_APPS/src/LabSwitch` only decides which lab process owns the USB cable. Mention it when you say who can open CDC. Do not audit it as a production service.

`JAVA_APPS/src/CertGenerator` is in scope where it creates the SAE root, the client CA, node identities, and the QKD PKCS#12 import. Do not line-audit it as a general PKI product.

Utimaco vendor jars and `ultimaco/` simulators are out of scope except for the PIN, bind address, and “software vs HSM” claims this tree documents.

### In scope — SE

- `stm32u535-trustzone-usb/docs/ACCESS_POINTS.md`, `SECURITY.md`, `COMMANDS.md`, `COMMUNICATION.md`, `TROPIC.md`, `HARDWARE.md`, `HOW_TO_RUN.md`
- `stm32u535-trustzone-usb/Secure/Core/Src/`, `Secure/Core/Inc/` — application logic (`se_*.c`, `secure_*.c`, `secure_nsc.c`, `se_tls_nsc_callable.c`)
- `stm32u535-trustzone-usb/NonSecure/Core/Src/` — especially `main.c`, `tls_usb_io.c`
- `stm32u535-trustzone-usb/Secure_nsclib/`
- Linker maps: `Secure/STM32U535CCTX_FLASH.ld`, `Secure/STM32U535CCTX_RAM.ld`, `NonSecure/STM32U535CCTX_FLASH.ld`, `NonSecure/STM32U535CCTX_RAM.ld`
- `Secure/wolfSSL/user_settings.h`, `Secure/Core/Inc/libtropic_user_config.h`
- `SE_firmware.ioc` only for TrustZone / pin / peripheral security attributes. Do not treat it as something to edit

### In scope — SAE

- `JAVA_APPS/src/SaeNode/` (main, not a line-by-line test audit). Start with `Node.java`, `ProvisionSession.java`, `InputHandler.java`, `OriginShareCheck.java`, `OriginShareAccess.java`, `interNodeCommunication/RmiManager.java`, `NodeCommands.java`, `NodeCommandsService.java`, `se/SeSessionUplink.java`, `se/SeSessionBinding.java`, `se/SeKemFill.java`, `se/SeProvisionAck.java`, `se/SeManage.java`, `qkd/QkdPadMaterialFetcher.java`, `db/ClientRecordStateRepository.java`, `tls/SoftwareTls.java`, `tls/HsmNodeTls.java`
- `JAVA_APPS/src/SaeNode/main/resources/sae-nodes.json` and `db/migration/`
- `JAVA_APPS/src/TerminalBridge/` (`UsbFrame`, `SeUsbLink`, `SeUsbTls`) where SAE and the chip share the frame
- `JAVA_APPS/README.md`, `JAVA_APPS/src/SaeNode/README.md`, `JAVA_APPS/docs/FLOWCHARTS.md`, `specs/sae-provision/`
- Env examples under `JAVA_APPS/env/example/` for defaults (`NODE_HOSTNAME`, `HSM_DEVICE`, passwords). Do not read real `env/*.env` if they contain live PINs. Do not print secret values.

### In scope — USER (light)

Only enough to answer two questions:

1. **Physical access to the home PC.** What files and prompts hold the owner key, the reset password, the PIN, `pairing-key.hex`, and (in lab) `client_ca.p12`? Name the paths in `UserApp` (`OwnerTls`, `ChipInit`, `UserApplication`) and the file modes. Stop when you can say what an attacker at the keyboard or with the disk obtains.
2. **Wi-Fi.** Does UserApp listen (ServerSocket, RMI, HTTP, mDNS)? If it only opens USB CDC and is a TLS server on that serial stream, say the household Wi-Fi attacks the PC, not a UserApp port. Do not trace every encrypt/decrypt UI branch.

### Out of scope for a line audit

- `libtropic/` internals, examples, and tests — in scope only where this firmware calls them or ships a factory SH0 choice
- `Middlewares/Third_Party/wolfSSL_wolfSSL_wolfSSL/` and the top-level `wolfssl/` tree — in scope only at the integration (`user_settings.h`, what the Secure image enables, how keys are loaded and wiped)
- `Drivers/`, CMSIS, CubeMX HAL outside “did TrustZone and the clocks match the claims”
- `Secure/Debug/`, `NonSecure/Debug/`
- Side channels (power, EM, timing), fault injection, and a CVE sweep of wolfSSL or Bouncy Castle. Name them under zbytková rizika. Do not invent measurements you did not take
- A full review of UserApp command parsing, colors, or lab panes

## Attacker models (use both)

**A — operator with the cable and, in the lab, the debug probe.** No quantum computer. Can open USB CDC, strap BOOT0, attach SWD while `RDP = 0xAA`, probe SPI, cut power, and replace the NonSecure image if they can write flash. On the SAE host they can be a local user, a second process on the same machine, or a peer on a network if the process listens. On the USER PC they can be someone with the disk or the session.

**B — the post-quantum attacker from** `docs/SECURITY.md`**.** Can break X25519 and P-256. Cannot break ML-KEM-768, ML-DSA-44, or AES-256-GCM / SHA-384 used as specified. Still cannot skip PIN + MAC-and-Destroy by mathematics alone. Verify that split against the code. If a path treats a classical signature as the device’s post-quantum identity, that is a finding under model B. The QKD hop is `CLASSICAL` on purpose: an attack that only breaks that hop must say so and must not be written as a break of `PROVISION` TLS.

An attack that needs model B must say so. An attack that works with model A must not be dressed up as a post-quantum result.

## Two contexts

State every finding as **lab board**, **locked board**, **lab SAE**, **cabled SAE**, **home PC**, or **both**, as applicable.

- Lab board: `TZEN = 1`, `RDP = 0xAA`, `BOOT_LOCK = 0`, `HDP1EN = 0`, factory SH0 still valid until `MANAGE PAIRING`.
- Locked board: readout protection and boot lock as in `HOW_TO_RUN.md` and in the hardware chapter you write. SWD and ROM bootloader are gone. USB, a malicious NonSecure image already in flash, SPI on the board, and the SAE host remain.
- Lab SAE: `NODE_HOSTNAME` default `127.0.0.1`, HSM simulator on localhost, `INIT LAB` may hold the client CA on a developer machine.
- Cabled SAE: the hardware chapter’s firewall, no Wi-Fi, HSM not on a wireless network, client CA not on the home PC.

## Mandatory checks — SE

Work through these in order. For each check, record in **Postup a dílčí výsledky** what you opened and whether a bypass exists. A “holds” result needs the function that enforces it.

### 1. Enrollment, then mutation

Compare the **first write** of an asset with every **later write**. The question is whether a caller can create a valid state and then update it into a malicious one.

Assets to diff: owner SPKI, reset-password hash, SAE CA (flash page 21), device certificate, on-chip ML-DSA key, Tropic ECC slot 0, ML-KEM seed (R-MEM 510), PIN NVM (R-MEM 511), pairing private key, peer table, `fill_id`, OTP cursors, Unix time floor.

Known doors, verify rather than trust this list: unsigned `OWNER SET`; `MANAGE` commands `KEM INIT`, `KEYGEN`, `PEER ADD`, `PEER REMOVE`, `CREDS SAE`, `INSERT SIGNED CSR`, `OWNER REPLACE`, `PAIRING`, `PAIRING LOAD`; `PROVISION` downlink; encrypt/decrypt consume. Look for a second write that skips a check the first write had (or the reverse: a strict update that the create path never applied).

`se_owner_set` refuses when `se_nv_has_owner()` is already set. Confirm that is the close of `OWNER SET`, and that `CREDS SAE` (`do_creds_sae` → `se_creds_set_sae_ca`) can still replace the CA afterwards with no comparison to the stored CA. If the enrolled owner can retarget `PROVISION`, say which trust boundary moved. Identity for that call is the MANAGE pin in `se_tls_user_pin_peer`, not a second factor.

### 2. Where authority comes from

For every sensitive field, name the source. Attacker-controlled sources include the USB payload, the `<unix>` argument, NonSecure’s choice of TLS mode, and anything a USB host can spoof. Hardware- or Secure-world sources include NV written only by Secure, Tropic M&D slots, the session exporter, and the on-chip ML-DSA key.

Flag any rule that decides “who is SAE” or “who is the owner” from data the USB peer just supplied, unless an earlier enrollment closed that door and the later path checks the stored value.

### 3. The product must still be able to do its job

The rules are broken if SAE cannot provision, or USER cannot encrypt and decrypt, without a workaround that skips authentication. Peer add/remove must match the peer table the downlink and the console actually use. Record a finding when the only way to complete enrollment is an unsigned path that stays open after the device is in service.

Also check the opposite failure: a control that looks strict and is never reached (dead check, wrong mode, check after the burn).

### 4. Exhaustion

Look for missing bounds that let a peer waste RAM, flash, or one-time pads:

- CDC frame length, 160-byte command line, 16 KiB RX ring, 8 KiB TX ring, command queue depth
- `OWNER SET` and `MANAGE` body sizes versus those rings
- pad count, peer count, nickname length, certificate and SPKI length
- OTP consume as an **availability** attack (advance-then-erase, skip-ahead on decrypt)
- a provision that wipes R-MEM 0–509

A missing cap on secret material is nízká only when the caller is already the owner of that session. A missing cap that lets any USB host burn pads or fill the ring is at least střední.

### 5. Type and length checks

Frames are `u16le magic 0x6767 | u8 type | u16le length | payload`. MANAGE is `u8 cmd | u8 pin_len | pin | u16le body_len | body`. Check integer overflow on lengths, accepted ranges, version fields (`uplink` / `downlink`), and that a wrong type cannot be parsed as a TLS record or as a different command. A path that checks types on create and casts freely on update is the same class of bug as a ruleset that types fields only in `create`.

### 6. Field allow-list is not identity

Restricting which fields a command may change does **not** say who may send it. For each mutating command, answer both questions. If any authenticated-looking USB host, or any NonSecure image, can change another principal’s asset (owner, SAE CA, pairing key, pads) without an ownership or pin check, that is an integrity bug. Map this to access points `SE-L1`, `SE-L2`, `SE-L3`, `SE-N1`.

`MANAGE` is owner-pinned and has **no device client certificate**. Judge that on purpose: pinning to the enrolled owner SPKI is the identity check. Confirm the pin is the stored key (`se_tls_user_pin_peer` reads `se_nv_get_owner_spki`), not the key the peer presents as authority by itself. Confirm `PROVISION` loads the SAE CA from flash (`tls_load_provision_ca` / `se_creds_get_sae_ca`), not a CA shipped in the same session. Confirm encrypt/decrypt call the same pin (`tls_app_encrypt_enter`, `tls_app_decrypt_enter`) and still load the device client certificate.

### 7. Bootstrap and added privileges

There is no hardcoded admin email in this firmware. Do not import that exception.

Bootstrap is unsigned USB `OWNER SET`: first empty slot wins, and it can install the owner SPKI and the SAE CA. Score that door on its own. Then ask whether a later admin can widen access:

- `CREDS SAE` replaces the CA that `PROVISION` trusts
- `OWNER REPLACE` swaps the owner if the reset password matches (`se_owner_replace`). Read what it wipes and what it keeps (pairing)
- `PAIRING LOAD` restores an exported pairing private key. Compare its checks with `PAIRING`
- `KEYGEN` replaces ECC slot 0 when occupied
- `PEER ADD` inserts up to eight peers

A bootstrap that is unsigned **once**, then closed, is different from a bootstrap that still accepts `OWNER SET` after enrollment. Read the code.

### 8. TrustZone and the NSC veneer

NonSecure must not be able to read Secure RAM, flash page 21, or flash page 22. Confirm the linker and SAU story far enough to see that those regions are Secure. Then audit the veneers in `Secure_nsclib/se_tls_nsc.h` and `se_tls_nsc_callable.c`: packet size, which calls exist, whether NonSecure chooses TLS mode and Unix time (`SECURE_TlsStart_nsc_call`), and whether mutating operations (`KEYGEN`, `KEM INIT`, peer edits) are reachable as NSC entries or only after `MANAGE`.

A correct statement is allowed to be subtle: compromising NonSecure does not reveal Secure keys, and NonSecure can still point a session at the wrong peer or proxy USB bytes. Write that as a residual if the code matches it. Write it as a vulnerability if a veneer returns key material, skips a pin, or lets NonSecure supply the owner or the CA.

### 9. Session binding

`PROVISION`, `ENCRYPT`, `DECRYPT`, and `MANAGE` share one CDC port. Check:

- idle type `0x01` is dropped until a mode is armed
- a type `0x00` command during TLS is queued, not parsed as a handshake record
- the uplink is bound to this TLS exporter, not to a previous session (`se_tropic_session_uplink`, exporter wiped)
- encrypt/decrypt pin the peer SPKI to the enrolled owner and still use a device client certificate
- `MANAGE` does not accept an SAE leaf (same owner pin; no client CA loaded on that mode)
- the Unix time argument cannot move the NV floor backward (`se_time_set_unix`). Read the `unix_utc < floor` branch: it must not arm a session on a clock that moved backward, and it must not report success while still applying the stale value. Certificates are judged against the floor
- DTR drop, RX overflow, and TLS end return the parser to command mode without leaving a half-armed session that still accepts pipe bytes

### 10. OTP and cursor integrity

Confirm advance-then-erase (`se_tropic_OTP_xor_consume`), no rewind, no mixing of encrypt and decrypt halves, `fill_id` inside the pad HKDF, and Tropic mcounters matched to MCU NV (`DEVICE_TAMPERED` on mismatch). A power cut during consume may burn a pad; call that a residual if the code does it on purpose, a vulnerability if the cursor and the pad can disagree in a way that reuses keystream.

### 11. Secret lifetime

Trace where `secure_dwk`, the ML-DSA secret, the pairing private key, the PIN, `final_key`, and the TLS exporter are stored and wiped. Plaintext in flash page 22 is a known design. Do not “discover” it without also saying what an attacker still cannot do (pads need the PIN and live M&D). Do find any path that copies those secrets into NonSecure RAM, a console reply, a log line, or a buffer that is not wiped. `PAIRING` returns the private key once on the MANAGE TLS session (`pairing_ok_msg`). That is the export. Confirm it is not also printed on the type `0x00` console.

### 12. Physical doors, without repeating the datasheet

Use `ACCESS_POINTS.md` IDs `SE-P1` through `SE-P7` and `SE-T1`. The useful questions are narrow:

- Before `PAIRING`, is factory SH0 the L3 key, and is that private key in the SDK (`libtropic_user_config.h`, prod0 vs `SE_TROPIC_SH0_ENG`)?
- After `PAIRING`, does L3 require the private key that now sits in MCU NV, and does `PAIRING LOAD` put it back with weaker checks than `PAIRING`?
- Can SPI observation of M&D traffic, plus model B, reveal PIN material, or only the KMAC outputs the protocol already treats as sensitive?
- Does the firmware expose a USB DFU class or a UART command path? The docs say no. Check the NonSecure USB descriptors and the IOC.

### 13. Oracles

Compare console replies (`failed`, `empty`, `refused`, `ok`) with `MANAGE` status bytes (`PIN_FAIL`, `SLOT_OCC`, …). If the ASCII line reveals occupancy, enrollment state, or remaining pad kilobytes to an unauthenticated host, rate it. Public keys and `CLIENT CSR` are medium by the access-point review; do not call them kritická unless they disclose a secret.

### 14. Claim versus code (SE)

Pick the hardening bullets in `docs/SECURITY.md` sections 1–8 and the review questions at the bottom of `docs/ACCESS_POINTS.md` (the SE rows and the SAE rows that the firmware doc could only state as a contract). For each, write one line in the procedure chapter: **holds**, **contradicted**, or **now testable in this tree** (the old prompt said “not enforceable” because SAE was absent; that excuse is gone for the Java). A contradicted bullet is a finding even if the design discussion is otherwise careful.

## Mandatory checks — SAE

The firmware contract is not a substitute for the Java. `ACCESS_POINTS.md` SAE-4 describes the uplink check in one sentence. `SECURITY.md` describes another. `SeSessionBinding.verify` is the code. Follow the code.

### 15. Who may complete PROVISION

Trace `Node` USB accept → TLS (`PURE_PQC`, client auth) → `SeSessionUplink.readAndVerify` → operator `SELECT` / `CONFIRM` → `ProvisionSession` → downlink → device ack → `ORIGIN_PROVISIONED`.

Answer:

- Is the device certificate checked against `client_ca`, and does SAE also bind the uplink client hash to that certificate (`SeSessionBinding`)?
- Can any leaf under `client_ca` pull pads, or only a device the operator selected?
- Is pad plaintext in process memory, in SQLite (`shared_key_material`), or in a log? If SQLite stores it, is it HSM-wrapped, and who can unwrap?
- Does a failed origin fill leave `RECORD_SHARED` that is deleted after 5 minutes, and can that delete or reclaim hand the same keystream to a second device?
- Are uplink version and downlink version checked on both sides (`SeConstants` vs firmware LV)?

### 16. Peer SAE and RMI

`NodeCommands`: `ping`, `relay`, `getRecordMetadata`, `synchronize`, `lockFetch`, `insert`, `removeRecord`. For each, say who may call it and what pad material it returns.

- TLS profile is `PURE_PQC` and client auth is required on the server factory. Confirm.
- Bind address: `NODE_HOSTNAME` versus `createServerSocket` with a null bind. A listener on all interfaces is a finding for a cabled SAE and a residual for a lab process that is supposed to be localhost only if the docs claim localhost.
- `issuingSaeId` and client hashes are arguments. Confirm the callee does not trust them without the TLS peer identity.
- `relay` must not be an open pipe for pad bytes or for operator decisions.

### 17. QKD and the classical hop

`QkdPadMaterialFetcher` and the KME client. Where the pad bytes go, whether they are logged, and that this hop is `CLASSICAL`. Model B applies here. Do not treat a break of X25519 on the KME link as a break of device `PROVISION` unless the fetched bytes then skip the SAE’s own sealing.

### 18. Operator stdin and local files

`InputHandler` / the terminal. No network listener for `SELECT`. Local user on the SAE host is model A. SQLite mode `0600` is only as good as the directory. `application_log` must not contain pad plaintext, PINs, or HSM keys. `APP_LOG=FULL` is a lab switch.

### 19. Secrets on the SAE host

`EnvSecrets`, `env/example/`, `certs/ca/root-ca.p12`, `certs/ca/client_ca.p12`, node PEMs, HSM key names. Production guidance already says not to put `HSM_PIN` in the environment. Confirm the code path really prompts when the variable is unset. A default PIN compiled into source is a finding. A PIN only in the README’s simulator procedure is a poznámka plus a line in the hardware chapter.

### 20. Claim versus code (SAE)

`SaeNode/README.md` TLS table, `FLOWCHARTS.md` provision sequence, and `ACCESS_POINTS.md` SAE-1–SAE-6. One line each: **holds**, **contradicted**, or **docs were written before the Java was in this tree** (then you close the question from Java).

## Mandatory checks — USER (stop early)

### 21. Physical

List the files an attacker with the home PC can read: owner PKCS#12 or PEM, lab client CA, device cert, `pairing-key.hex`, CSR hex. Note POSIX mode where the code sets one (`ChipInit` writes `pairing-key.hex` as `rw-------`). Say whether the PIN and the reset password are only typed, or also stored. This is the compromise of the **owner**. It is not, by itself, a compromise of SAE pad storage. Severity follows from what those files actually unlock on the chip (owner-pinned `MANAGE`, including `CREDS SAE` and `PAIRING LOAD`).

### 22. Wi-Fi

Search UserApp for sockets and URL clients. Expected result, which you must confirm rather than assume: no listen port; USB CDC only; TLS is terminated on that stream. If that holds, the Wi-Fi section is a short residual: malware or file sync on the PC, not a UserApp service. If you find a listen port, it becomes a normal finding.

Do not build attack scenarios that require a line audit of `ENCRYPT` framing in UserApp. The chip side of those commands is already in the SE checks.

## Attack scenarios

Write scenarios as sequences, not as control names. Minimum set, each traced to a real function or method. Drop a scenario the code makes impossible, and say why in the procedure chapter. Add a scenario if you find a door this table missed.

| ID | Idea to try |
| --- | --- |
| AT-1 | USB host enrolls itself with `OWNER SET` after the legitimate owner, or instead of them |
| AT-2 | Enrolled owner uses `CREDS SAE` or a second `OWNER SET` to point `PROVISION` at a different CA |
| AT-3 | Peer completes `PROVISION` without a leaf under the CA stored on page 21, or replays an old downlink / old uplink. Check both the chip and `SeSessionBinding` |
| AT-4 | `ENCRYPT` or `DECRYPT` runs with a different SPKI than the enrolled owner, or `MANAGE` is used to consume pads or read the PIN out of band |
| AT-5 | NonSecure firmware arms the wrong TLS mode or forwards bytes, and you show exactly which keys it still cannot read |
| AT-6 | Cursor rewind, half mix, or `fill_id` reuse yields keystream reuse or a skipped burn |
| AT-7 | Flash dump of pages 21–22 plus Tropic R-MEM, with and without the PIN, against the compromise ladder in `SECURITY.md` |
| AT-8 | SPI before pairing with the published SH0 key; SPI after pairing with only the pairing public key |
| AT-9 | Resource exhaustion: oversized frame, queued commands, repeated decrypt skip-ahead, provision wipe |
| AT-10 | `PAIRING` key captured on the TLS session, then `PAIRING LOAD` after reflash |
| AT-11 | A second SAE, or any client that can complete RMI, calls `insert`, `getRecordMetadata`, `removeRecord`, or `relay` and obtains or replaces pad material |
| AT-12 | SAE listens beyond localhost, or the KME hop is reached across Wi-Fi, and model A or B uses that path |
| AT-13 | Origin share reclaim or a second `PROVISION` delivers the same keystream twice, or delivers it to a device that was not the operator’s selection |
| AT-14 | Attacker with the home PC reads `user.p12` / `pairing-key.hex` and uses them on USB. State what that unlocks, and that Wi-Fi does not add a second UserApp service if none is listening |

## Mitigations

Each mitigation must name the asset, the boundary, and the mechanism (for example: refuse `OWNER SET` once page 22 is valid; require the device client certificate on `MANAGE`; bind `CREDS SAE` to a fresh owner authentication; move `secure_dwk` into a hardware unique key; set `BOOT_LOCK` and `RDP`; bind the RMI socket to the cable address; keep the client CA off the home PC). Mark mitigations the firmware can do alone versus mitigations that need SAE, the operator, or silicon option bytes.

Hardware parameters that are purely operational belong in **Doporučené hardwarové a provozní parametry**, and the mitigation chapter points there instead of repeating the table. A code change (bind address, refuse `CREDS SAE` without a second check) stays in the mitigation chapter.

Do not propose editing CubeMX-generated pin setup, `HAL_*_MspInit`, or files under `Debug/`. If a mitigation is “change option bytes”, cite `HOW_TO_RUN.md` and leave the procedure to the operator.

## Residuals

Separate:

- residuals you accept because the design says so (PIN entropy vs 8 M&D tries, plaintext secrets in page 22, SAE sees pad plaintext before it is sealed, USB has no login for read-only commands, QKD hop is classical, lab `RDP = 0xAA`)
- residuals of your method (no board, no power traces, wolfSSL and Bouncy Castle not line-audited, HSM simulator not a cHSM, UserApp not line-audited)
- residuals that remain even after your proposed mitigations and after the locked-board and cabled-SAE parameters

## Procedure you must follow

Record these steps in **Postup a dílčí výsledky**. Each step has a result paragraph. Do not paste a plan you did not execute.

1. Read `ACCESS_POINTS.md` and build the asset list from the “What it reaches” columns, then add SAE assets that exist only in Java (SQLite key material, HSM keys, root CA private key, RMI). Result: asset table draft. Note the stale “SaeNode is not in this tree” sentence.
2. Read `SECURITY.md` and the SaeNode README TLS table. Result: claim list you will confirm.
3. Map Secure vs NonSecure from the linker scripts and NSC headers. Result: trust-boundary table.
4. Trace USB parse and command dispatch (`NonSecure` CDC → NSC → Secure console). Result: which commands are unsigned, which arm TLS, which mutate.
5. Trace `OWNER SET`, credential storage, and the “already enrolled” predicate. Result: whether bootstrap closes, and whether `CREDS SAE` reopens the CA.
6. Trace `PROVISION` on the chip (CA, exporter, uplink, downlink, R-MEM write) and the same session in `ProvisionSession` / `SeSessionUplink` / `SeSessionBinding`. Result: who can inject pads.
7. Trace `ENCRYPT`, `DECRYPT`, `MANAGE` authentication and the nine `MANAGE` commands. Result: identity check per command.
8. Trace OTP consume, cursors, mcounters, `fill_id`, and wipe range. Result: integrity properties that hold or fail.
9. Trace PIN KDF and M&D, and the buffers those keys occupy. Result: where the PIN can be observed (chip, USER TLS, SAE or not).
10. Trace pairing, SH0 selection, and `PAIRING LOAD`. Result: who can speak L3.
11. Trace RMI: `RmiManager.start`, socket bind, `NodeCommandsService` methods, origin-share checks. Result: who can call each method and whether the listener is local.
12. Trace QKD fetch and `shared_key_material`. Result: where pad plaintext sits and how it is wrapped.
13. USER only: file inventory and a socket search. Result: physical compromise list, and whether Wi-Fi has a UserApp port.
14. Walk SE checks 1–14 and SAE checks 15–20 against that evidence. Result: one row per item, holds or finding ID.
15. Write scenarios AT-1–AT-14 (and extras) only from that evidence. Result: the scenario chapter.
16. Assign severity, mitigations, the hardware-parameter chapter, and residuals. Result: the last chapters.

## Evidence rules

- Cite `path` and function or method name. Line numbers when you have them.
- Quote only the few lines needed to show the check or its absence. Do not paste crypto implementations or key material.
- If you did not run the board or the Java processes, say so in Úvod. Static reading can still support a vulnerability when the control is missing in source. Do not claim you exploited silicon or the network.
- If two files disagree, show both and follow the one that runs.
- Prefer a short finding you can defend over a long one you inferred.
- Paths in the document are relative to `one-time-pad-keychain/`.

## Done when

- `one-time-pad-keychain/docs/security-analysis/bezpecnostni-analyza.tex` exists and LuaLaTeX finishes without error
- The required chapters are present and non-empty, including **Doporučené hardwarové a provozní parametry** with the SE option bytes and the SAE cable / firewall / no-Wi-Fi sheet
- Postup a dílčí výsledky contains the sixteen steps with a result for each
- Every finding has severity, scenario ID, evidence, and a mitigation
- Lab board, locked board, lab SAE, cabled SAE, and home PC are distinguished
- USER is a short physical-and-Wi-Fi section, not a third full audit
- You did not modify anything outside `one-time-pad-keychain/docs/security-analysis/`
