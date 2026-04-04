-- Project statistics: view count and demo click count
-- Run this in Supabase Dashboard > SQL Editor

ALTER TABLE projects ADD COLUMN IF NOT EXISTS view_count integer default 0;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS click_count integer default 0;

CREATE OR REPLACE FUNCTION increment_view_count(p_id uuid)
RETURNS integer
LANGUAGE sql
AS $$
  UPDATE projects SET view_count = COALESCE(view_count, 0) + 1 WHERE id = p_id RETURNING view_count;
$$;

CREATE OR REPLACE FUNCTION increment_click_count(p_id uuid)
RETURNS integer
LANGUAGE sql
AS $$
  UPDATE projects SET click_count = COALESCE(click_count, 0) + 1 WHERE id = p_id RETURNING click_count;
$$;
