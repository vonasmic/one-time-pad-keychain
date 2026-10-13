ALTER TABLE client_record_state ADD COLUMN pad_plain_len INTEGER NOT NULL DEFAULT 0
    CHECK (pad_plain_len >= 0 AND pad_plain_len <= 65535);
