-- Run once in the Supabase SQL Editor.
create table if not exists sync_operations (
  op_id       text primary key,          -- X-Offline-Op-Id sent by the browser
  method      text,
  path        text,
  status_code int,
  user_id     text,
  applied_at  timestamptz not null default now()
);
-- If your backend uses the anon key and RLS is on, either use the service role key
-- (like your other tables) or run:  alter table sync_operations disable row level security;