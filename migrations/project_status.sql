-- Add project_status column for user-facing project lifecycle status.
-- Values: finished, in_progress, just_started, needs_help
ALTER TABLE projects ADD COLUMN IF NOT EXISTS project_status TEXT DEFAULT 'finished';

-- RLS policy: allow authenticated users to update only their own projects
CREATE POLICY IF NOT EXISTS "Users can update own projects"
  ON projects FOR UPDATE
  USING (auth.jwt() ->> 'email' IS NOT NULL)
  WITH CHECK (author = current_setting('request.jwt.claims', true)::json ->> 'user_metadata' ->> 'handle');
