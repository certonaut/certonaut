CREATE TABLE renewal_info
(
    cert_id           TEXT PRIMARY KEY NOT NULL,
    fetched_at        DATETIME         NOT NULL, -- RFC3339 TEXT
    fetched_at_unix   REAL             NOT NULL GENERATED ALWAYS AS (unixepoch(fetched_at, 'subsec')) STORED,
    renewal_time      DATETIME         NOT NULL, -- RFC3339 TEXT
    renewal_time_unix REAL             NOT NULL GENERATED ALWAYS AS (unixepoch(renewal_time, 'subsec')) STORED,
    next_update       DATETIME         NOT NULL, -- RFC3339 TEXT
    next_update_unix  REAL             NOT NULL GENERATED ALWAYS AS (unixepoch(next_update, 'subsec')) STORED
);
CREATE TABLE renewals
(
    id             INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    cert_id        TEXT                              NOT NULL,
    outcome        INT                               NOT NULL,
    failure        TEXT,
    timestamp      DATETIME                          NOT NULL, -- RFC3339 TEXT
    timestamp_unix REAL                              NOT NULL GENERATED ALWAYS AS (unixepoch(timestamp, 'subsec')) STORED
);
CREATE INDEX renewals_timestamp ON renewals (cert_id, timestamp_unix);