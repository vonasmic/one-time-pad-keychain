# SAE / SE / Terminal Flowcharts

High-level flowcharts for the key-exchange process. These reflect the actual system behavior but omit internal implementation details.

---

## 1. Main end-to-end flow

```mermaid
flowchart TD
    subgraph clientSE [Client SE]
        Start([Start])
        Connect[Connect to origin SAE]
        SendKeys[Send own public key and possible peer keys]
        ReceiveKeys[Receive secret keys]
        End([End])
    end

    subgraph originSAE [Origin SAE]
        WaitConn[Wait for client connection]
        UserChoice[Get user selection via terminal]
        CheckDB{Record state in database?}
        NewExchange[Fetch keys from QKD and sync with peer SAE]
        ExistingKeys[Handle existing or shared record]
        ReturnKeys[Return keys to client]
        NoKeys[End without returning keys]
    end

    subgraph targetSAE [Peer SAE]
        SyncKeys[Receive sync request from origin SAE]
        FetchPeerKeys[Fetch matching keys from QKD]
        StoreKeys[Store key material locally]
        UpdateDB[Update database state]
    end

    subgraph external [External]
        QKD[QKD 014]
        DB[(Database)]
    end

    Start --> Connect --> SendKeys
    SendKeys --> WaitConn
    WaitConn --> UserChoice
    UserChoice --> CheckDB

    CheckDB -->|No record or can start new| NewExchange
    CheckDB -->|Record already exists| ExistingKeys
    CheckDB -->|Cannot proceed| NoKeys

    NewExchange -.-> QKD
    NewExchange --> SyncKeys
    SyncKeys --> FetchPeerKeys
    FetchPeerKeys -.-> QKD
    FetchPeerKeys --> StoreKeys --> UpdateDB
    UpdateDB -.-> DB
    NewExchange -.-> DB
    NewExchange -->|Success| ReturnKeys
    NewExchange -->|Failure| NoKeys

    ExistingKeys -->|Keys returned| ReturnKeys
    ExistingKeys -->|No action| NoKeys

    ReturnKeys --> ReceiveKeys --> End
    NoKeys --> End
```

---

## 2. SE ↔ SAE communication

```mermaid
sequenceDiagram
    participant SE as Client SE
    participant SAE as Origin SAE

    SE->>SAE: Connect over TLS
    SAE-->>SE: Secure channel established

    SE->>SAE: Send public key and list of possible peer keys
    Note over SAE: User selects target peer and SAE via terminal

    alt New key exchange
        SAE-->>SE: Return secret keys
    else Existing shared keys
        SAE-->>SE: Return previously stored keys
    else Cannot proceed
        SAE-->>SE: Close without keys
    end

    SAE-->>SE: Close connection
```

---

## 3. Terminal ↔ SAE communication

The terminal is operated locally on the SAE machine. The SAE builds selection lists from the client payload and its configured peer SAEs.

```mermaid
flowchart TD
    subgraph sae [Origin SAE]
        ReceivePayload[Receive client key data]
        BuildLists[Prepare SAE list and client list]
        WaitChoice[Wait for user selection]
        ApplyChoice[Apply selected peer SAE and client]
        ReusePrompt{Keys already shared?}
        AskDelete[Ask whether to delete and start over]
        DeleteRecords[Delete old records]
        Continue[Continue key exchange]
    end

    subgraph terminal [Terminal]
        ShowSaeList[Show peer SAE options]
        PickSae[User picks SAE]
        ShowClientList[Show client options]
        PickClient[User picks client]
        ConfirmDelete[User confirms deletion y/n]
    end

    ReceivePayload --> BuildLists --> ShowSaeList
    ShowSaeList --> PickSae --> ShowClientList
    ShowClientList --> PickClient --> WaitChoice
    WaitChoice --> ApplyChoice --> ReusePrompt

    ReusePrompt -->|No| Continue
    ReusePrompt -->|Yes| AskDelete --> ConfirmDelete
    ConfirmDelete -->|Yes| DeleteRecords --> Continue
    ConfirmDelete -->|No| StopFlow[Stop without new keys]
```

---

## 4. SAE database persistence decisions

The database tracks **record state** (not the key material itself). Key material is stored on the peer SAE.

### 4a. Can a new record be started?

```mermaid
flowchart TD
    Begin([Check database for client hash pair])
    Exists{Record exists?}

    Exists -->|No| AllowNew[Allow new record]
    Exists -->|Yes| State{Current state?}

    State -->|Complete and same peer| AlreadyExists[Record already exists]
    State -->|Complete but different peer| SharedElsewhere[Shared with different SAE]
    State -->|In progress and expired| AllowNew
    State -->|In progress and owned by this SAE| AllowNew
    State -->|In progress by another SAE| Blocked[Cannot start now]
    State -->|In progress, different peer| SharedElsewhere
```

### 4b. What happens after the check?

```mermaid
flowchart TD
    Start([After database check])
    Result{Result?}

    Result -->|New record allowed| FetchQKD[Fetch keys from QKD]
    FetchQKD --> SyncPeer[Sync with peer SAE]
    SyncPeer --> PeerOK{Peer sync OK?}
    PeerOK -->|Yes| MarkComplete[Mark record complete in database]
    MarkComplete --> ReturnKeys[Return keys to client]
    PeerOK -->|No| Rollback[Remove incomplete record]
    Rollback --> NoKeys[No keys returned]

    Result -->|Record already exists| Issuer{Is this SAE the issuer?}
    Issuer -->|Yes| AskUser[Ask user to delete and retry]
    AskUser -->|Yes| DeleteAll[Delete local and peer records]
    DeleteAll --> Start
    AskUser -->|No| NoKeys

    Issuer -->|No| LoadStored[Load stored keys from peer SAE]
    LoadStored --> Found{Keys found?}
    Found -->|Yes| ReturnKeys
    Found -->|No| NoKeys

    Result -->|Cannot proceed| NoKeys
```

### 4c. Peer SAE side

```mermaid
flowchart TD
    Start([Receive sync from origin SAE])
    CanStore{Can store new record?}
    CanStore -->|No| Reject[Reject sync]
    CanStore -->|Yes| GetKeys[Fetch keys from QKD]
    GetKeys --> SaveKeys[Save key material]
    SaveKeys --> MarkComplete[Mark record complete in database]
    MarkComplete --> Done([Confirm to origin SAE])
    GetKeys -->|Error| Cleanup[Remove incomplete record]
    Cleanup --> Reject
```

---

## Component overview

```mermaid
flowchart LR
    SE[Client SE]
    OriginSAE[Origin SAE]
    Terminal[Terminal]
    PeerSAE[Peer SAE]
    QKD[QKD 014]
    DB[(Database)]

    SE <-->|TLS| OriginSAE
    OriginSAE <-->|User input| Terminal
    OriginSAE <-->|Inter-SAE sync| PeerSAE
    OriginSAE --> QKD
    PeerSAE --> QKD
    OriginSAE --> DB
    PeerSAE --> DB
```
