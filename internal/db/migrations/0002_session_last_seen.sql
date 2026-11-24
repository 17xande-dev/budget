-- +goose Up
-- When a session was last used, for the idle limit (a session unused for a week
-- ends; the absolute end is still expires_at, fixed at sign-in). The column is
-- written at most once a minute by the request that finds it stale.
--
-- Existing sessions are backfilled to the moment of this migration, so the
-- column's arrival signs nobody out: each gets a full idle window from now.
-- The DEFAULT is only what ADD COLUMN needs for a NOT NULL column; every insert
-- sets the value.
ALTER TABLE sessions ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT '';
UPDATE sessions SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');

-- +goose Down
-- Rolling the binary back to the previous release needs this first: it refuses a
-- database newer than it knows. The previous release has no idle limit, so the
-- column is simply dropped.
ALTER TABLE sessions DROP COLUMN last_seen_at;
