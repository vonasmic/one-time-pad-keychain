CREATE TABLE IF NOT EXISTS application_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    logged_at  TEXT    NOT NULL,
    level      TEXT    NOT NULL,
    logger     TEXT    NOT NULL,
    thread     TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    thrown     TEXT
);

CREATE INDEX IF NOT EXISTS application_log_logged_at_idx ON application_log (logged_at);
