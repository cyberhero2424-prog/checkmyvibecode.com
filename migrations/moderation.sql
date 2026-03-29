-- Project Submission Moderation Migration
-- Run this in the Supabase Dashboard > SQL Editor
-- This adds a status column so new submissions start as 'pending'
-- and only 'approved' projects are visible to the public.

-- ── 1. Add status column ──────────────────────────────────────────────────────
alter table public.projects
  add column if not exists status text not null default 'pending';

-- ── 2. Approve all existing projects so they stay visible ─────────────────────
-- Guard: only backfills on the very first run (when no 'approved' rows exist yet).
-- Safe to re-run: skips the update if approved rows are already present.
do $$
begin
  if not exists (select 1 from public.projects where status = 'approved' limit 1) then
    update public.projects set status = 'approved' where status = 'pending';
  end if;
end;
$$;

-- ── 3. Update the public SELECT policy ───────────────────────────────────────
-- Drop the existing open SELECT policy and replace it with one that only
-- returns approved projects.  Policy names may differ across environments,
-- so we drop both common variants defensively.

drop policy if exists "Public projects are viewable by everyone." on public.projects;
drop policy if exists "Anyone can read projects" on public.projects;

create policy "Anyone can read approved projects"
  on public.projects for select
  using (status = 'approved');

-- ── Done ─────────────────────────────────────────────────────────────────────
-- After running this:
--   1. Set SUPABASE_SERVICE_KEY in Replit Secrets (from Supabase Dashboard > Settings > API)
--   2. Set ADMIN_PASSWORD in Replit Secrets (any strong password you choose)
--   3. Access /admin on your site to review pending submissions
