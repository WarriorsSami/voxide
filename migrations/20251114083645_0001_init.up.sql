-- meta table with verifier fields
CREATE TABLE meta(
     version        INTEGER NOT NULL,
     kdf_salt       BLOB    NOT NULL,
     kdf_params     TEXT    NOT NULL,   -- JSON (KdfParams)
     created_at     TEXT    NOT NULL,   -- RFC3339
     verifier_nonce BLOB    NOT NULL,   -- 24B
     verifier_ct    BLOB    NOT NULL    -- AEAD(ct of "voxide-ok")
);

-- entries table
CREATE TABLE entries(
    id          TEXT PRIMARY KEY,   -- UUID stored as TEXT
    service     TEXT NOT NULL,
    username    TEXT NOT NULL,
    nonce       BLOB NOT NULL,      -- 24B XChaCha20
    ciphertext  BLOB NOT NULL,      -- AEAD(ct + tag)
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(service, username)       -- Enforce unique (service, username) pairs
);

CREATE INDEX idx_entries_service_user ON entries(service, username);
