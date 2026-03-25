-- Bookmarks table migration
-- Run this in the Supabase Dashboard > SQL Editor

create table if not exists public.bookmarks (
  project_id uuid not null references public.projects(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (project_id, user_id)
);

-- Row-Level Security
alter table public.bookmarks enable row level security;

-- Authenticated users can read their own bookmarks
create policy "Users can read own bookmarks"
  on public.bookmarks for select
  using (auth.uid() = user_id);

-- Authenticated users can insert their own bookmarks
create policy "Users can insert own bookmarks"
  on public.bookmarks for insert
  with check (auth.uid() = user_id);

-- Authenticated users can delete their own bookmarks
create policy "Users can delete own bookmarks"
  on public.bookmarks for delete
  using (auth.uid() = user_id);
