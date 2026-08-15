CREATE TABLE IF NOT EXISTS client_record_state(
    client_hash1         TEXT NOT NULL,
    client_hash2         TEXT NOT NULL,

    date_of_creation     TIMESTAMPTZ NOT NULL,

    record_availability  TEXT NOT NULL
        CHECK (record_availability IN ('RECORD_IN_PROGRESS', 'RECORD_AVAILABLE')),

    sae_id               TEXT NOT NULL,
    issuing_sae_id       TEXT,

    PRIMARY KEY (client_hash1, client_hash2)
);

CREATE TABLE IF NOT EXISTS shared_key_material(
    client_hash1   TEXT NOT NULL,
    client_hash2   TEXT NOT NULL,
    ciphertext     BYTEA NOT NULL,
    gcm_iv         BYTEA NOT NULL,
    gcm_tag_bits   INT  NOT NULL CHECK (gcm_tag_bits = 128),
    hsm_key_alias  TEXT NOT NULL,
    PRIMARY KEY (client_hash1, client_hash2),
    FOREIGN KEY (client_hash1, client_hash2)
        REFERENCES client_record_state (client_hash1, client_hash2)
        ON DELETE CASCADE
);
