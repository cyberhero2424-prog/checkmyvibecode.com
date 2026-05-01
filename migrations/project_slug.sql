-- Add a URL-friendly slug column to projects.
-- Slugs are generated from the project name at submission time (e.g. "needlecast-file-manager").
-- Existing projects keep NULL until they are re-submitted or a backfill is run.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS slug TEXT UNIQUE;
CREATE INDEX IF NOT EXISTS idx_projects_slug ON projects(slug) WHERE slug IS NOT NULL;
