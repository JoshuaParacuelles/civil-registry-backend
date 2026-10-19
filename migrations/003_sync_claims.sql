-- Run once in the Supabase SQL Editor.
-- Adds the columns routes/sync.py needs for claim-first replay.

create table if not exists sync_operations (
  op_id       text primary key,
  method      text,
  path        text,
  status_code int,
  user_id     text,
  applied_at  timestamptz not null default now()
);

ALTER TABLE sync_operations ADD COLUMN IF NOT EXISTS status     text;
ALTER TABLE sync_operations ADD COLUMN IF NOT EXISTS claimed_at timestamptz;

UPDATE sync_operations SET status = 'applied' WHERE status IS NULL;

CREATE INDEX IF NOT EXISTS sync_operations_status_claimed_idx
  ON sync_operations (status, claimed_at);

-- Kung ang backend mo gamit anon key ug naka-on ang RLS, i-uncomment ang linya sunod:
-- ALTER TABLE sync_operations DISABLE ROW LEVEL SECURITY;