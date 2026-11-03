# SAE / USER / SE Flowcharts

High-level flowcharts. **SAE** (SaeNode) is provision / QKD fill.
**USER** (UserApp) is encrypt / decrypt / manage. UserApp is not an SAE. These
show the intended design, not method-level control flow.

---

## 1. Main end-to-end provision flow (device ↔ SAE)

Origin device gets a new share. The origin SAE locks the pair on both SAEs
(lower SAE ID first), fetches the keys from its KME and transfers them to the
device while it renews both locks every 60 s. After the device ack it renews
both locks, the peer SAE writes `KEYS_AVAILABLE(token)`, then the origin SAE
writes `KEYS_AVAILABLE(token)`, and it renews both locks again. Only then does
the terminal "share complete" line appear (`Loading 100% … Share successful.`).
The locks are released, remote first. A later peer device is section 6d.

```mermaid
flowchart TD
    subgraph clientSE [Origin client SE]
        Start([Start])
        Connect[Connect to origin SAE]
        SendKeys[Send own public key and possible peer keys]
        ReceiveKeys[Receive secret keys]
        Ack[Ack]
        End([End])
    end

    subgraph originSAE [Origin SAE]
        WaitConn[Wait for client]
        UserChoice[Operator selects peer]
        Lock[Lock the pair: lower SAE ID first, then higher]
        Fetch[Fetch keys from the origin KME]
        SendOrigin[Send keys to origin device, renew both locks every 60 s]
        Renew1[Renew both locks]
        OriginWrite[Origin KEYS_AVAILABLE token]
        Renew2[Renew both locks]
        SuccessLine[Share complete]
        Release[Release both locks, remote first]
        NoKeys[End without share complete]
    end

    subgraph targetSAE [Peer SAE]
        PeerLock[Grant or refuse the pair lock]
        StoreKeys[Resolve key IDs at its KME and store material]
        PeerAvailable[Peer KEYS_AVAILABLE token]
    end

    subgraph external [External]
        QKD[QKD 014]
        DB[(Record state)]
    end

    Start --> Connect --> SendKeys --> WaitConn --> UserChoice --> Lock
    Lock -.-> PeerLock
    Lock -->|Both locks held| Fetch
    Lock -->|Refused| NoKeys
    Fetch -.-> QKD
    Fetch --> SendOrigin --> ReceiveKeys --> Ack --> Renew1
    Renew1 --> StoreKeys
    StoreKeys -.-> QKD
    StoreKeys --> PeerAvailable -.-> DB
    PeerAvailable --> OriginWrite -.-> DB
    OriginWrite --> Renew2 --> SuccessLine --> Release --> End
    Fetch -->|Failure| NoKeys
    SendOrigin -->|No ack or lock lost| NoKeys
    Renew1 -->|Lock lost| NoKeys
    StoreKeys -->|Failure, peer row removed by token| NoKeys
    NoKeys --> Release
```

---

## 2. SE ↔ SAE communication (`PROVISION` only)

Device TLS client to SaeNode over USB CDC.
This is **not** encrypt / decrypt — those sessions are device ↔ USER.
The full decision tree is [`diagrams/provision_flow.drawio`](../../diagrams/provision_flow.drawio).

```mermaid
sequenceDiagram
    participant SE as Client SE
    participant SAE as SAE
    participant OP as Operator (stdin)
    participant PEER as Other SAE (RMI)

    Note over SE: USB ASCII PROVISION {unix}. TLS arms only with owner, device cert and key, SAE CA and ML-KEM key
    SE->>SAE: TLS 1.3 mTLS over CDC (PURE_PQC)
    Note over SE,SAE: SE checks the SAE leaf against the SAE CA. SAE checks the device leaf against client_ca
    SE->>SAE: Uplink LV v5 (session_sig, ecc_pub, client_hash, slot_size, pad_count, fill_id, ML-KEM pk, peers)
    Note over SE: Erases its QKD R-MEM slots
    SE-->>SAE: TROPIC_WIPE_FINISHED
    Note over SAE: Uplink check (SeSessionUplink.readAndVerify): client_hash = SHA-384(TLS SPKI ‖ ecc_pub), ECDSA over SHA-384(client_hash ‖ exporter)
    SAE->>OP: Select peer SAE and peer device
    OP-->>SAE: Selection
    SAE->>PEER: lockPair (lower SAE ID first, then higher)
    PEER-->>SAE: granted or refused

    alt New share for the origin device
        Note over SAE: KME keys, renew both locks
        SAE->>SE: ML-KEM-768 sealed LV downlink v3 (decrypt_half ORIGIN)
        SE-->>SAE: SE_OK
        SAE->>PEER: renewPair, insert KEYS_AVAILABLE(token)
        Note over SAE: Origin KEYS_AVAILABLE(token), renew both, share complete
    else Stored share for the peer device
        SAE->>PEER: getRecordMetadata
        Note over SAE: Both rows KEYS_AVAILABLE with the same token and naming each other
        SAE->>PEER: deleteRecord (remote first), then the local row
        SAE->>SE: ML-KEM-768 sealed LV downlink v3 (decrypt_half PEER)
        SE-->>SAE: SE_OK
    else Lock refused, other SAE unreachable, or share not consistent
        Note over SAE: No downlink
    end

    SAE->>PEER: releasePair (remote first), then the local lock
    SAE-->>SE: Close TLS
```

---

## 3. SE ↔ USER communication (`ENCRYPT` / `DECRYPT` / `MANAGE`)

Device TLS client to **UserApp**. UserApp is not an SAE. PIN and OTP payloads
never go to SaeNode.

```mermaid
sequenceDiagram
    participant SE as Client SE
    participant USER as UserApp

    Note over SE,USER: USB ASCII ENCRYPT / DECRYPT / MANAGE {unix}, then TLS 1.3 (PURE_PQC) over CDC
    SE->>USER: TLS handshake. SE pins the UserApp leaf SPKI to the enrolled owner key (no CA)
    alt ENCRYPT or DECRYPT
        SE->>USER: Device leaf (mTLS). UserApp checks it against client_ca
    else MANAGE
        Note over SE,USER: No device client cert
    end
    USER-->>SE: Secure channel established

    alt ENCRYPT
        USER->>SE: PIN + plaintext
        SE-->>USER: OTP ciphertext chunks
    else DECRYPT
        USER->>SE: PIN + encrypt reply
        SE-->>USER: plaintext chunks
    else MANAGE
        USER->>SE: unsigned cmd + optional PIN + body
        SE-->>USER: status
    end

    SE-->>USER: close_notify
    USER-->>SE: close_notify
```

---

## 4. Operator stdin on SaeNode

Operator SELECT / CONFIRM / NOTIFY runs in the SaeNode process (stdin), **not**
UserApp and not a separate TLS gateway. The SAE builds selection lists from the
SAE directory and the client payload, then prompts on the same console. The
prompts follow `ProvisionSession.process`: a pair without a local row asks
"Generate new keys now?", except right after a delete.

```mermaid
flowchart TD
    subgraph sae [Origin SAE]
        ReceivePayload[Receive the verified uplink]
        ShowSaeList[Show peer SAE options from the SAE directory]
        PickSae[Operator picks SAE]
        ShowClientList[Show peer devices from the uplink]
        PickClient[Operator picks peer device]
        Local{Local row for this pair?}
        GenPrompt{"No shared keys were found for this pair. Generate new keys now?"}
        Lock[Lock both SAEs: lower SAE ID first, then higher]
        Busy["NOTIFY: Another operation for this device pair is in progress on an SAE. Retry later."]
        TargetRow{Target row names another SAE?}
        RemoteDelete{"This will permanently delete those keys. Do you really want to delete them and generate new ones?"}
        Generate[Generating new keys: KME, device transfer, peer then origin KEYS_AVAILABLE]
        Keys([Keys for the origin device])
        Names{Row names the selected SAE?}
        OwnIssuer{Row issued by this SAE?}
        AskRecreate{"Shared keys already exist with SAE ... Delete them and generate new keys?"}
        UseExisting{"Shared keys already exist with SAE ... Did you mean to use those keys?"}
        ReallyDelete{"This will permanently delete those keys. Do you really want to delete them and generate new ones?"}
        OperatorDelete[Operator delete: lock both SAEs, compare-and-delete on the shown token, remote first]
        Changed["NOTIFY: The shared keys changed while you were deciding. Nothing was deleted; check them again."]
        Deliver[Deliver the stored share, section 6d]
        Kept[Existing keys were kept. No keys were sent to the device]
    end

    ReceivePayload --> ShowSaeList --> PickSae --> ShowClientList --> PickClient --> Local
    Local -->|No| GenPrompt
    GenPrompt -->|Yes, or skipped after a delete| Lock
    GenPrompt -->|No| ShowSaeList
    Lock -->|Refused| Busy
    Lock -->|Local row appeared| Local
    Lock -->|Both held| TargetRow
    TargetRow -->|No| Generate --> Keys
    TargetRow -->|Yes, locks released| RemoteDelete
    RemoteDelete -->|Yes| OperatorDelete
    RemoteDelete -->|No| Kept
    Local -->|Yes| Names
    Names -->|Yes| OwnIssuer
    OwnIssuer -->|Yes| AskRecreate
    OwnIssuer -->|No| Deliver
    AskRecreate -->|Yes| OperatorDelete
    AskRecreate -->|No| Kept
    Names -->|No| UseExisting
    UseExisting -->|Yes| Deliver
    UseExisting -->|No| ReallyDelete
    ReallyDelete -->|Yes| OperatorDelete
    ReallyDelete -->|No| Kept
    OperatorDelete -->|Deleted, generate prompt skipped| Local
    OperatorDelete -->|Token differs| Changed --> Local
    OperatorDelete -->|Lock refused| Busy
```

---

## 5. Record states and pair locks

Each SAE keeps one `client_record_state` row per client pair. The key material
is in `shared_key_material`. A row has a single state,
`KEYS_AVAILABLE` (`AtomicRecordStateMap.RecordAvailability`), and carries the
`lease_token` of the operation that wrote it and its `issuing_sae_id`.

| State | Set by | Meaning |
| --- | --- | --- |
| `KEYS_AVAILABLE` | peer: `insert(record, token)` over RMI, key IDs resolved at its KME and written in one transaction under the caller's lease; then origin: `writeOrigin` under its own lease, both after the device `SE_OK` | The SAE holds its half of the share written by the operation with that token. A share is usable only when both rows are `KEYS_AVAILABLE`, carry the same token and name each other |

```mermaid
stateDiagram-v2
    [*] --> KEYS_AVAILABLE: write under both pair locks (peer first, then origin)
    KEYS_AVAILABLE --> [*]: peer-device delivery (remote first)
    KEYS_AVAILABLE --> [*]: operator delete (compare-and-delete on the shown token)
    KEYS_AVAILABLE --> [*]: orphan removal or retention
```

**Pair locks.** Every operation on a client pair (new share, peer-device
delivery, operator delete) holds a lock on both SAEs of the pair
(`PairLocks`, `PairLockRegistry`). The lock is keyed by the sorted pair of
client hashes and held in memory. The operation takes the lock of the SAE with
the lower ID first, then the higher one, over RMI `lockPair` for a remote SAE.
A refusal releases the first lock and ends the operation with the busy
message; nobody waits for a lock. A lock is a lease of 5 minutes with a random
128-bit token and the issuing SAE; the holder renews both leases every 60 s
(`renewPair`) and before and after each commit step (`PairOperation.checkpoint`).
A failed renewal aborts the operation and closes the device session. Every row
write and delete runs in one `BEGIN IMMEDIATE` transaction that checks the
token, expiry and issuer of the lease. The operation releases both locks by
token, remote first (`releasePair`).

Retention: `RecordRetention` runs at node start and then every 24 hours. It
deletes `client_record_state` rows older than `RECORD_RETENTION_DAYS`
(default 14), each only while nobody holds the pair lock, and their
`shared_key_material` rows go with them (`ON DELETE CASCADE`). Reads treat such
rows as absent.

---

## 6. SAE database persistence decisions

Origin publishes the **reversed** hash pair to the peer SAE (`(peerHash, myHash)`);
each node looks up only the pair it stored.

### 6a. Can a new share start?

`ProvisionSession.newShare` under both pair locks. "Target" is the other SAE
named in the request.

```mermaid
flowchart TD
    Begin([Operator chose to generate keys])
    Lock{Both pair locks acquired?}
    Lock -->|No| Busy[Busy message, nothing written]
    Lock -->|Yes| Local{Local row present?}
    Local -->|Yes| Restart[Release the locks, ask the operator again]
    Local -->|No| Target{Target row names another SAE?}
    Target -->|Yes| Ask[Release the locks, operator delete prompt for the target row]
    Target -->|No, or names this SAE| AllowNew[Start new share; the target row of this SAE is overwritten]
```

### 6b. Origin device: new share

```mermaid
flowchart TD
    Start([New share allowed, both locks held])
    Kme[Fetch key IDs and pads from the origin KME]
    Kme -->|Fail| NoKeys[No keys sent]
    Kme -->|OK| Guard1[Renew both locks]
    Guard1 --> Send[Send keys to origin device, renew both locks every 60 s]
    Send -->|No ack, timeout or lock lost| NoKeys
    Send -->|SE_OK| Guard2[Renew both locks]
    Guard2 --> Peer[Peer KEYS_AVAILABLE token]
    Peer --> Origin[Origin KEYS_AVAILABLE token]
    Origin --> Guard3[Renew both locks]
    Guard3 --> Done([Share complete])
    Guard2 -->|Lock lost| Warn[Warning: device holds keys, share not recorded on both SAEs]
    Peer -->|Fail| Undo[Delete the peer row by token] --> Warn
    Origin -->|Fail| Undo
    Guard3 -->|Lock lost| Warn
    Done --> Release[Release both locks, remote first]
    Warn --> Release
    NoKeys --> Release
```

### 6c. Peer SAE during the exchange

```mermaid
flowchart TD
    Start([Receive insert with token from origin])
    Caller{Header SAE ID is the calling SAE?}
    Caller -->|No| Reject[Reject]
    Caller -->|Yes| Lease{Caller holds the lease with this token?}
    Lease -->|No| Lost[Reject: lock lost]
    Lease -->|Yes| GetKeys[Get keys by key IDs from its KME]
    GetKeys -->|Error| Reject
    GetKeys -->|OK| Save{"One transaction: lease still valid? Save HSM-encrypted key material and KEYS_AVAILABLE token"}
    Save -->|No, nothing written| Lost
    Save -->|Yes| Avail[Peer KEYS_AVAILABLE token]
    Avail --> Done([Confirm to origin])
```

### 6d. Later: peer device

A second device is filled from the **stored** peer material only when both
rows are `KEYS_AVAILABLE` with the same token and name each other, checked
under both pair locks at use time. Deletes are remote-first: the origin row is
removed over RMI before the local row.

```mermaid
flowchart TD
    Start([Peer has stored material])
    Own{Row issued by this SAE?}
    Own -->|Yes| Hold[Do not send]
    Own -->|No| Fit{Pads fit this chip?}
    Fit -->|No| Hold
    Fit -->|Yes| Lock{Both pair locks acquired?}
    Lock -->|Refused or unreachable| Hold
    Lock -->|Yes| Same{Local token equals the shown token?}
    Same -->|No| Hold
    Same -->|Yes| Origin[RMI getRecordMetadata on the origin]
    Origin -->|Origin unreachable| Hold
    Origin --> Decide{Both KEYS_AVAILABLE, same token, same issuer, naming each other?}
    Decide -->|Yes| Payload[Read the stored payload]
    Payload -->|Missing| Hold
    Payload --> RemoteFirst[RMI deleteRecord on the origin by token]
    RemoteFirst -->|DELETED| Read[Delete the local row]
    RemoteFirst -->|Other| Hold
    Read --> Send[Send stored keys to peer device]
    Decide -->|No| Orphan[Delete the orphan, remote first. Provision both devices again]
    Send --> Release[Release both locks, remote first]
    Hold --> Release
    Orphan --> Release
```

---

## 7. Component overview

The deployment design and its install steps (the user PC, where the user
application enrolls the keychain, and one SAE; the second SAE is the same
design) are drawn in
[`diagrams/deployment.drawio`](../../diagrams/deployment.drawio). Trust anchors,
truststores and pins are in [`diagrams/trust_pki.drawio`](../../diagrams/trust_pki.drawio);
the RMI startup checks and one pinned call are in
[`diagrams/rmi_pinning.drawio`](../../diagrams/rmi_pinning.drawio).
