CREATE TABLE client_record_state(
    client_hash1        TEXT NOT NULL,
    client_hash2        TEXT NOT NULL,

    date_of_creation     TIMESTAMPTZ NOT NULL,

    record_availability  TEXT NOT NULL
        CHECK (record_availability IN ('RECORD_IN_PROGRESS', 'RECORD_AVAILABLE')),

    sae_id              TEXT NOT NULL,
    issuing_sae_id      TEXT,

    PRIMARY KEY (client_hash1, client_hash2)
);
