-- Forum tables migration
-- Run this in the Supabase Dashboard > SQL Editor

-- ── forum_threads ──────────────────────────────────────────
create table if not exists public.forum_threads (
  id           uuid primary key default gen_random_uuid(),
  title        text not null,
  body         text not null,
  author_handle text not null,
  author_id    uuid not null references auth.users(id) on delete cascade,
  upvotes      int  not null default 0,
  reply_count  int  not null default 0,
  created_at   timestamptz not null default now()
);

alter table public.forum_threads enable row level security;

create policy "Anyone can read forum threads"
  on public.forum_threads for select
  using (true);

create policy "Auth users can insert own threads"
  on public.forum_threads for insert
  with check (auth.uid() = author_id);

create policy "Authors can delete own threads"
  on public.forum_threads for delete
  using (auth.uid() = author_id);

-- No direct client UPDATE policy — counters are updated via SECURITY DEFINER RPCs below.

-- ── forum_replies ───────────────────────────────────────────
create table if not exists public.forum_replies (
  id           uuid primary key default gen_random_uuid(),
  thread_id    uuid not null references public.forum_threads(id) on delete cascade,
  body         text not null,
  author_handle text not null,
  author_id    uuid not null references auth.users(id) on delete cascade,
  created_at   timestamptz not null default now()
);

alter table public.forum_replies enable row level security;

create policy "Anyone can read forum replies"
  on public.forum_replies for select
  using (true);

create policy "Auth users can insert own replies"
  on public.forum_replies for insert
  with check (auth.uid() = author_id);

create policy "Authors can delete own replies"
  on public.forum_replies for delete
  using (auth.uid() = author_id);

-- ── forum_thread_upvotes ────────────────────────────────────
create table if not exists public.forum_thread_upvotes (
  thread_id uuid not null references public.forum_threads(id) on delete cascade,
  user_id   uuid not null references auth.users(id) on delete cascade,
  primary key (thread_id, user_id)
);

alter table public.forum_thread_upvotes enable row level security;

create policy "Auth users can read own forum upvotes"
  on public.forum_thread_upvotes for select
  using (auth.uid() = user_id);

create policy "Auth users can insert own forum upvotes"
  on public.forum_thread_upvotes for insert
  with check (auth.uid() = user_id);

create policy "Auth users can delete own forum upvotes"
  on public.forum_thread_upvotes for delete
  using (auth.uid() = user_id);

-- ── RPC: update thread upvote count (SECURITY DEFINER — bypasses RLS safely) ──
-- Called from client after inserting/deleting a row in forum_thread_upvotes.
-- Only recounts from forum_thread_upvotes; cannot modify content fields.
create or replace function public.update_thread_upvote_count(p_thread_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.forum_threads
  set upvotes = (
    select count(*) from public.forum_thread_upvotes where thread_id = p_thread_id
  )
  where id = p_thread_id;
end;
$$;

-- ── RPC: update thread reply count (SECURITY DEFINER — bypasses RLS safely) ──
-- Called from client after inserting a row in forum_replies.
-- Only recounts from forum_replies; cannot modify content fields.
create or replace function public.update_thread_reply_count(p_thread_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.forum_threads
  set reply_count = (
    select count(*) from public.forum_replies where thread_id = p_thread_id
  )
  where id = p_thread_id;
end;
$$;
