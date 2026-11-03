-- SAE node schema.
--
-- client_record_state: one row per client pair as this SAE sees it. A row is written only while
-- the provisioning operation holds the in-memory pair lease on both SAEs, so the only persisted
-- state is KEYS_AVAILABLE. sae_id is the counterpart SAE, issuing_sae_id the SAE whose operation
-- wrote the share, lease_token that operation's token; a share is usable only when both SAEs
-- hold the same token.
--
-- shared_key_material: the sealed (HSM AES-GCM) key material of a share, stored at the
-- counterpart of the issuing SAE; removed together with its row.
--
-- application_log: node log records (SqliteLogHandler).

CREATE TABLE application_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    logged_at  TEXT    NOT NULL,
    level      TEXT    NOT NULL,
    logger     TEXT    NOT NULL,
    thread     TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    thrown     TEXT
);

CREATE INDEX application_log_logged_at_idx ON application_log (logged_at);

CREATE TABLE client_record_state (
    client_hash1         TEXT NOT NULL,
    client_hash2         TEXT NOT NULL,
    date_of_creation     TEXT NOT NULL,
    record_availability  TEXT NOT NULL
        CHECK (record_availability IN ('KEYS_AVAILABLE')),
    sae_id               TEXT NOT NULL,
    issuing_sae_id       TEXT NOT NULL,
    lease_token          TEXT NOT NULL,
    pad_plain_len        INTEGER NOT NULL DEFAULT 0
        CHECK (pad_plain_len >= 0 AND pad_plain_len <= 65535),
    PRIMARY KEY (client_hash1, client_hash2)
);

CREATE TABLE shared_key_material (
    client_hash1   TEXT NOT NULL,
    client_hash2   TEXT NOT NULL,
    ciphertext     BLOB NOT NULL,
    gcm_iv         BLOB NOT NULL,
    gcm_tag_bits   INT  NOT NULL CHECK (gcm_tag_bits = 128),
    hsm_key_alias  TEXT NOT NULL,
    PRIMARY KEY (client_hash1, client_hash2),
    FOREIGN KEY (client_hash1, client_hash2)
        REFERENCES client_record_state (client_hash1, client_hash2)
        ON DELETE CASCADE
);
