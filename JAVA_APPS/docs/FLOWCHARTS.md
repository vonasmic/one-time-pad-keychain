# SAE / USER / SE Flowcharts

High-level flowcharts. **SAE** (SaeNode) is provision / QKD fill.
**USER** (UserApp) is encrypt / decrypt / manage. UserApp is not an SAE. These
show the intended design, not method-level control flow.

---

## 1. Main end-to-end provision flow (device ↔ SAE)

Origin device gets a new share. Both SAEs become **RECORD_SHARED**, then the origin
device is filled. After the ack both rows become **ORIGIN_PROVISIONED**. The terminal
success line is printed only after both marks return. A later peer
device is section 6d — not this chart.

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
        NewExchange[Reserve pair, fetch QKD, sync peer]
        BothAvailable[Both SAEs RECORD_SHARED]
        SendOrigin[Send keys to origin device]
        MarkProvisioned[Both ORIGIN_PROVISIONED]
        SuccessLine[Terminal success line]
        NoKeys[End without keys]
    end

    subgraph targetSAE [Peer SAE]
        SyncKeys[Accept sync]
        StoreKeys[Fetch QKD and store material]
        PeerAvailable[Peer RECORD_SHARED]
    end

    subgraph external [External]
        QKD[QKD 014]
        DB[(Record state)]
    end

    Start --> Connect --> SendKeys --> WaitConn --> UserChoice --> NewExchange
    NewExchange -.-> QKD
    NewExchange -.-> DB
    NewExchange --> SyncKeys --> StoreKeys
    StoreKeys -.-> QKD
    StoreKeys --> PeerAvailable -.-> DB
    PeerAvailable --> BothAvailable
    BothAvailable --> SendOrigin --> ReceiveKeys --> Ack --> MarkProvisioned
    MarkProvisioned -.-> DB
    MarkProvisioned --> SuccessLine --> End
    NewExchange -->|Failure| NoKeys --> End
    SendOrigin -->|No ack| NoKeys
```

---

## 2. SE ↔ SAE communication (`PROVISION` only)

Device TLS client to SaeNode over USB CDC.
This is **not** encrypt / decrypt — those sessions are device ↔ USER.

```mermaid
sequenceDiagram
    participant SE as Client SE
    participant SAE as SAE

    SE->>SAE: Connect over TLS (PROVISION)
    SAE-->>SE: Secure channel established
    SE->>SAE: Send public key and list of possible peer keys
    Note over SAE: Operator selects target peer on stdin

    alt New share for the origin device
        Note over SAE: Both SAEs become RECORD_SHARED
        SAE-->>SE: Return secret keys
        SE-->>SAE: Ack
        Note over SAE: Both rows ORIGIN_PROVISIONED
    else Stored share for the peer device
        Note over SAE: Only if both rows are ORIGIN_PROVISIONED
        SAE-->>SE: Return stored secret keys
    else Origin not yet Provisioned
        SAE-->>SE: Close without keys
    else Cannot proceed
        SAE-->>SE: Close without keys
    end

    SAE-->>SE: Close connection
```

---

## 3. SE ↔ USER communication (`ENCRYPT` / `DECRYPT` / `MANAGE`)

Device TLS client to **UserApp**. UserApp is not an SAE. PIN and OTP payloads
never go to SaeNode.

```mermaid
sequenceDiagram
    participant SE as Client SE
    participant USER as UserApp

    Note over USER: USB ASCII ENCRYPT / DECRYPT / MANAGE then TLS over CDC
    SE->>USER: Connect over TLS (owner-pinned)
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
client payload and its configured peer SAEs, then prompts on the same console.

```mermaid
flowchart TD
    subgraph sae [Origin SAE]
        ReceivePayload[Receive client key data]
        BuildLists[Prepare SAE list and client list]
        ShowSaeList[Show peer SAE options]
        PickSae[User picks SAE]
        ShowClientList[Show client options]
        PickClient[User picks client]
        ApplyChoice[Apply selected peer SAE and client]
        ReusePrompt{Origin already Provisioned?}
        AskDelete[Ask whether to delete and start over]
        ConfirmDelete[User confirms deletion y/n]
        DeleteRecords[Delete old records]
        SilentRetry[Available leftover: delete and start new, no prompt]
        Continue[Continue key exchange]
    end

    ReceivePayload --> BuildLists --> ShowSaeList
    ShowSaeList --> PickSae --> ShowClientList
    ShowClientList --> PickClient --> ApplyChoice --> ReusePrompt

    ReusePrompt -->|No record| Continue
    ReusePrompt -->|Available leftover| SilentRetry --> Continue
    ReusePrompt -->|Provisioned| AskDelete --> ConfirmDelete
    ConfirmDelete -->|Yes| DeleteRecords --> Continue
    ConfirmDelete -->|No| StopFlow[Stop without new keys]
```

---

## 5. Record states

Each SAE keeps **record state** for a client pair (not the key bytes). Key
material lives on the **peer**. **ORIGIN_PROVISIONED** is written on both SAEs
after the origin device acknowledges the downlink. The peer device is filled
only from that state.

```mermaid
flowchart LR
    None([No record]) --> Sync[Synchronization]
    Sync --> Fetch[Fetching]
    Fetch --> Shared[RECORD_SHARED]
    Shared --> Prov[ORIGIN_PROVISIONED]
```

| State | Meaning |
| --- | --- |
| Synchronization | Pair reserved; exchange not locked yet |
| Fetching | Both sides locked; QKD fill in progress |
| RECORD_SHARED | Both databases hold keys. Incomplete until the origin device acks. Deleted after 5 minutes, and the key row goes with it |
| ORIGIN_PROVISIONED | Origin device acked. Both rows carry this state. Peer device may take the stored half |

---

## 6. SAE database persistence decisions

Origin publishes the **reversed** hash pair to the peer SAE (`(peerHash, myHash)`);
each node looks up only the pair it stored.

### 6a. Can a new share start?

```mermaid
flowchart TD
    Begin([Look up client pair])
    Exists{Record exists?}
    Exists -->|No| AllowNew[Start new share]
    Exists -->|Yes| Kind{Kind?}

    Kind -->|In progress and expired| AllowNew
    Kind -->|In progress and live| Wait[Cannot start now]
    Kind -->|RECORD_SHARED and stale| AllowNew
    Kind -->|RECORD_SHARED and fresh| Wait
    Kind -->|ORIGIN_PROVISIONED| Filled[Origin device already filled]
    Kind -->|Different peer| SharedElsewhere[Shared with another SAE]
```

### 6b. Origin device: new share

```mermaid
flowchart TD
    Start([New share allowed])
    Exchange[Fetch QKD and sync with peer]
    Exchange -->|Fail| Rollback[Drop incomplete records]
    Rollback --> NoKeys[No keys returned]
    Exchange -->|OK| BothAvail[Both SAEs RECORD_SHARED]
    BothAvail --> Send[Send keys to origin device]
    Send -->|Ack| Prov[Both ORIGIN_PROVISIONED]
    Send -->|No ack| LeftAvail[Leave RECORD_SHARED]
    Prov --> Done([Terminal success line])
    LeftAvail --> NextVisit[After 5 minutes the incomplete share is deleted]
```

### 6c. Peer SAE during the exchange

```mermaid
flowchart TD
    Start([Receive sync from origin])
    CanStore{Can store?}
    CanStore -->|No| Reject[Reject]
    CanStore -->|Yes| GetKeys[Fetch QKD]
    GetKeys -->|Error| Cleanup[Drop incomplete record]
    Cleanup --> Reject
    GetKeys -->|OK| Save[Save key material]
    Save --> Avail[Peer RECORD_SHARED]
    Avail --> Done([Confirm to origin])
```

### 6d. Later: peer device

A second device is filled from the **stored** peer material only when both
rows are **ORIGIN_PROVISIONED**. `RECORD_SHARED` on both SAEs is not enough.

```mermaid
flowchart TD
    Start([Peer has stored material])
    Both{Both ORIGIN_PROVISIONED?}
    Both -->|Yes| Send[Send stored keys to peer device]
    Both -->|RECORD_SHARED still fresh| Hold[Do not send]
    Both -->|Missing or stale| Clean[Drop the incomplete share]
    Both -->|Origin unreachable| Hold
```

---

## Component overview

```mermaid
flowchart LR
    SE[Client SE]
    UserApp[USER / UserApp]
    OriginSAE[Origin SAE]
    PeerSAE[Peer SAE]
    QKD[QKD 014]
    DB[(Database)]

    SE <-->|ENCRYPT / DECRYPT / MANAGE TLS| UserApp
    SE <-->|PROVISION TLS on CDC| OriginSAE
    OriginSAE <-->|Inter-SAE sync| PeerSAE
    OriginSAE --> QKD
    PeerSAE --> QKD
    OriginSAE --> DB
    PeerSAE --> DB
```
