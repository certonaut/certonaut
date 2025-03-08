CREATE TABLE ari
(
    fetched_at  DATETIME NOT NULL,
    result      TEXT     NOT NULL,
    next_update DATETIME NOT NULL
);
CREATE TABLE renewals
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    cert_id   TEXT                              NOT NULL,
    outcome   INT                               NOT NULL,
    failure   TEXT,
    timestamp DATETIME                          NOT NULL
);
CREATE TABLE notifications
(
    id        INT PRIMARY KEY NOT NULL,
    message   TEXT            NOT NULL,
    shown     BOOLEAN         NOT NULL,
    renewal   INT,
    timestamp DATETIME        NOT NULL,
    FOREIGN KEY (renewal) REFERENCES renewals ON DELETE NO ACTION
);