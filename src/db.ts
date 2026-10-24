import { Database } from "bun:sqlite";
import { chmodSync, existsSync } from "node:fs";

// Bump SCHEMA_VERSION and append to MIGRATIONS to change the schema; never edit a shipped step.
const MIGRATIONS: string[] = [
  `
  CREATE TABLE requests (
    id                TEXT PRIMARY KEY,
    fill_token_hash   TEXT NOT NULL UNIQUE,
    label             TEXT NOT NULL,
    reason            TEXT NOT NULL DEFAULT '',
    site              TEXT,
    fields            TEXT NOT NULL,
    level             TEXT NOT NULL,
    retention         TEXT NOT NULL,
    status            TEXT NOT NULL,
    fill_public_key   TEXT NOT NULL,
    fill_private_key  BLOB,
    secret            BLOB,
    use_count         INTEGER NOT NULL DEFAULT 0,
    decline_note      TEXT,
    created_at        INTEGER NOT NULL,
    link_expires_at   INTEGER NOT NULL,
    opened_at         INTEGER,
    filled_at         INTEGER,
    first_used_at     INTEGER,
    secret_expires_at INTEGER
  );
  CREATE TABLE use_tokens (
    token_hash  TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL,
    fields      TEXT NOT NULL,
    origin      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
  );
  CREATE TABLE approvals (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    request_id  TEXT NOT NULL,
    via         TEXT NOT NULL,
    purpose     TEXT NOT NULL DEFAULT '',
    origin      TEXT,
    fields      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    decided_at  INTEGER,
    redeemed_at INTEGER
  );
  CREATE TABLE audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    request_id TEXT,
    event      TEXT NOT NULL,
    detail     TEXT
  );
  CREATE TABLE origins_seen (
    origin     TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    fills      INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX audit_request ON audit (request_id);
  `,
];

export const SCHEMA_VERSION = MIGRATIONS.length;

export function openDb(path: string): Database {
  const db = new Database(path, { create: true, strict: true });
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;");
  for (const file of [path, `${path}-wal`, `${path}-shm`]) if (existsSync(file)) chmodSync(file, 0o600);
  const current = (db.query("PRAGMA user_version").get() as { user_version: number }).user_version;
  if (current > SCHEMA_VERSION) throw new Error(`locked.db is schema v${current}, newer than this build (v${SCHEMA_VERSION})`);
  for (let v = current; v < SCHEMA_VERSION; v++) {
    db.transaction(() => {
      db.exec(MIGRATIONS[v]!);
      db.exec(`PRAGMA user_version = ${v + 1}`);
    })();
  }
  return db;
}

/** True when the DB holds anything a lost master key would make unreadable. */
export function hasEncryptedData(db: Database): boolean {
  const row = db
    .query("SELECT COUNT(*) AS n FROM requests WHERE secret IS NOT NULL OR fill_private_key IS NOT NULL")
    .get() as { n: number };
  return row.n > 0;
}

export type RequestRow = {
  id: string;
  fill_token_hash: string;
  label: string;
  reason: string;
  site: string | null;
  fields: string;
  level: string;
  retention: string;
  status: string;
  fill_public_key: string;
  fill_private_key: Uint8Array | null;
  secret: Uint8Array | null;
  use_count: number;
  decline_note: string | null;
  created_at: number;
  link_expires_at: number;
  opened_at: number | null;
  filled_at: number | null;
  first_used_at: number | null;
  secret_expires_at: number | null;
};

export type UseTokenRow = {
  token_hash: string;
  request_id: string;
  fields: string;
  origin: string;
  created_at: number;
  expires_at: number;
  used_at: number | null;
};

export type ApprovalRow = {
  id: string;
  token_hash: string;
  request_id: string;
  via: string;
  purpose: string;
  origin: string | null;
  fields: string;
  status: string;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
  redeemed_at: number | null;
};
