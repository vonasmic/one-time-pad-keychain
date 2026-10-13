-- SQLite cannot alter a CHECK. Rebuild client_record_state so RECORD_PROVISIONED is legal.
-- Drop the child table first; a parent drop is rejected while shared_key_material references it.

CREATE TABLE shared_key_material_backup AS
SELECT client_hash1, client_hash2, ciphertext, gcm_iv, gcm_tag_bits, hsm_key_alias
FROM shared_key_material;

DROP TABLE shared_key_material;

CREATE TABLE client_record_state_new (
    client_hash1         TEXT NOT NULL,
    client_hash2         TEXT NOT NULL,
    date_of_creation     TEXT NOT NULL,
    record_availability  TEXT NOT NULL
        CHECK (record_availability IN (
            'RECORD_SYNCHRONIZATION',
            'RECORD_FETCHING_STARTED',
            'RECORD_AVAILABLE',
            'RECORD_PROVISIONED'
        )),
    sae_id               TEXT NOT NULL,
    issuing_sae_id       TEXT,
    pad_plain_len        INTEGER NOT NULL DEFAULT 0
        CHECK (pad_plain_len >= 0 AND pad_plain_len <= 65535),
    PRIMARY KEY (client_hash1, client_hash2)
);

INSERT INTO client_record_state_new (
    client_hash1, client_hash2, date_of_creation, record_availability,
    sae_id, issuing_sae_id, pad_plain_len
)
SELECT client_hash1, client_hash2, date_of_creation, record_availability,
       sae_id, issuing_sae_id, pad_plain_len
FROM client_record_state;

DROP TABLE client_record_state;

ALTER TABLE client_record_state_new RENAME TO client_record_state;

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

INSERT INTO shared_key_material (
    client_hash1, client_hash2, ciphertext, gcm_iv, gcm_tag_bits, hsm_key_alias
)
SELECT client_hash1, client_hash2, ciphertext, gcm_iv, gcm_tag_bits, hsm_key_alias
FROM shared_key_material_backup;

DROP TABLE shared_key_material_backup;
