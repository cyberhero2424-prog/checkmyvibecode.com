-- Project statistics: view count and demo click count
-- Run this in Supabase Dashboard > SQL Editor

ALTER TABLE projects ADD COLUMN IF NOT EXISTS view_count integer default 0;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS click_count integer default 0;
